use std::{
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Weak},
};

use anyhow::{bail, Context};
use buffers::ByteBuf;
use librqbit_core::torrent_metainfo::torrent_from_bytes;
use notify::Watcher;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tracing::{debug, error, error_span, trace, warn};

use crate::{AddTorrent, AddTorrentOptions, AddTorrentResponse, Session};

struct ThreadCancelEvent {
    mutex: parking_lot::Mutex<bool>,
    condvar: parking_lot::Condvar,
}

impl ThreadCancelEvent {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            mutex: parking_lot::Mutex::new(false),
            condvar: parking_lot::Condvar::new(),
        })
    }

    fn cancel(&self) {
        let mut g = self.mutex.lock();
        *g = true;
        self.condvar.notify_all();
    }

    fn wait_until_cancelled(&self) {
        let mut g = self.mutex.lock();
        while !*g {
            self.condvar.wait(&mut g);
        }
    }
}

async fn watch_adder(session_w: Weak<Session>, mut rx: UnboundedReceiver<AddTorrent<'static>>) {
    async fn add_one(
        session_w: &Weak<Session>,
        add_torrent: AddTorrent<'static>,
    ) -> anyhow::Result<()> {
        let session = match session_w.upgrade() {
            Some(s) => s,
            None => return Ok(()),
        };
        let res = session
            .add_torrent(
                add_torrent,
                Some(AddTorrentOptions {
                    overwrite: true,
                    ..Default::default()
                }),
            )
            .await?;
        match res {
            AddTorrentResponse::Added(_, _) => {}
            AddTorrentResponse::AlreadyManaged(_, _) => {
                debug!("already managed");
            }
            AddTorrentResponse::ListOnly(..) => bail!("bug: unexpected list only"),
        }
        Ok(())
    }

    while let Some(add_torrent) = rx.recv().await {
        if let Err(e) = add_one(&session_w, add_torrent).await {
            warn!("error adding torrent: {e:#}");
        }
    }
}

fn watch_thread(
    folder: PathBuf,
    tx: UnboundedSender<AddTorrent<'static>>,
    cancel_event: &ThreadCancelEvent,
) -> anyhow::Result<()> {
    fn read_and_validate_torrent(path: &Path) -> anyhow::Result<AddTorrent<'static>> {
        let mut buf = Vec::new();
        std::fs::File::open(path)
            .context("error opening")?
            .read_to_end(&mut buf)
            .context("error reading")?;
        torrent_from_bytes::<ByteBuf>(&buf).context("invalid .torrent file")?;
        Ok(AddTorrent::from_bytes(buf))
    }

    fn watch_cb(
        ev: notify::Result<notify::Event>,
        tx: &UnboundedSender<AddTorrent<'static>>,
    ) -> anyhow::Result<()> {
        trace!(event=?ev, "watch event");
        let ev = ev.context("error event")?;
        match ev.kind {
            notify::EventKind::Create(_) | notify::EventKind::Modify(_) => {}
            other => {
                debug!(kind=?other, paths=?ev.paths, "ignoring event");
                return Ok(());
            }
        }
        for path in ev.paths {
            if path.extension().and_then(|e| e.to_str()) != Some("torrent") {
                trace!(?path, "ignoring path");
                continue;
            }
            let add = match read_and_validate_torrent(&path) {
                Ok(add) => add,
                Err(e) => {
                    debug!(?path, "error validating torrent: {e:#}");
                    continue;
                }
            };

            if tx.send(add).is_err() {
                return Ok(());
            }
        }
        Ok(())
    }

    let mut watcher = notify::recommended_watcher(move |ev| {
        if let Err(e) = watch_cb(ev, &tx) {
            warn!("error processing watch event: {e:#}");
        }
    })
    .context("error creating watcher")?;
    watcher
        .watch(&folder, notify::RecursiveMode::Recursive)
        .context("error watching")?;
    cancel_event.wait_until_cancelled();
    debug!(?folder, "watcher thread done");
    Ok(())
}

impl Session {
    pub fn watch_folder(self: &Arc<Self>, watch_folder: &Path) {
        let session_w = Arc::downgrade(self);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.spawn(error_span!("watch_adder", ?watch_folder), async move {
            watch_adder(session_w, rx).await;
            Ok(())
        });

        let cancel_event = ThreadCancelEvent::new();
        let cancel_event_2 = cancel_event.clone();
        let cancel_token = self.cancellation_token().clone();
        crate::spawn_utils::spawn(
            "watch_cancel",
            error_span!("watch_cancel", ?watch_folder),
            async move {
                cancel_token.cancelled().await;
                trace!("canceling watcher");
                cancel_event.cancel();
                Ok(())
            },
        );

        let watch_folder = PathBuf::from(watch_folder);
        let session_span = self.rs();
        std::thread::spawn(move || {
            let span = error_span!(parent: session_span, "watcher", folder=?watch_folder);
            let _ = span.enter();
            if let Err(e) = watch_thread(watch_folder, tx, &cancel_event_2) {
                error!("error in watcher thread: {e:#}");
            }
        });
    }
}
