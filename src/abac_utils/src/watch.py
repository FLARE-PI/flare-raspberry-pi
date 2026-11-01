# ABAC Shared Directory watch
# Copyright (C) 2021 Hariyala Omakara Naga Sai Varshith

import time
import click
import json
from subprocess import Popen, PIPE
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from .common import check_root, load_path_scope
from .config import CONFIG_ROOT, CONFIG_OBJ_ATTRS_FILE
from .load import load_obj_attr

class Handler(FileSystemEventHandler):
    @staticmethod
    def on_any_event(event):
        if event.event_type == "deleted":
            # check if the deleted object has attributes, delete these attributes from config and reload
            with open(CONFIG_ROOT + CONFIG_OBJ_ATTRS_FILE) as f:
                attrs = json.load(f)
            resolved = str(Path(event.src_path).resolve())
            if resolved in attrs["objects"]:
                del attrs["objects"][resolved]
                print(f"Deleted attributes for file {resolved}")
            with open(CONFIG_ROOT + CONFIG_OBJ_ATTRS_FILE, 'w') as f:
                json.dump(attrs, f)
            load_obj_attr()

class PermissionHandler(FileSystemEventHandler):
    def __init__(self, watch_dir):
        self.watch_dir = watch_dir

    def on_created(self, event):
        p = Popen(["chmod", "-R" , "3770", self.watch_dir], stdout=PIPE, stderr=PIPE)
        output, error = p.communicate()
        if p.returncode != 0:
            print(f"Failed to chmod for {event.src_path}")

class ABACWatcher:
    def __init__(self, watch_dirs):
        self.watch_dirs = watch_dirs
        self.observer = Observer()

    def run(self):
        event_handler = Handler()
        for watch_dir in self.watch_dirs:
            self.observer.schedule(event_handler, watch_dir, recursive=True)
            self.observer.schedule(PermissionHandler(watch_dir), watch_dir, recursive=True)
        self.observer.start()
        try:
            print(f"Starting watching {', '.join(self.watch_dirs)}")
            while True:
                time.sleep(5)
        except Exception as e:
            self.observer.stop()
            print("An error occured while watching configured ABAC include paths")
            print(e)

        self.observer.join()

@click.command()
def watch():
    """
    ABAC Shared directory watcher service. Updates permissions based on file activities.
    Runs as a system service in the background.
    """
    check_root()
    scope = load_path_scope()
    watch_dirs = [path for path in scope["include"] if Path(path).is_dir()]
    if len(watch_dirs) == 0:
        print("No include directories configured for watcher. Nothing to watch.")
        return
    w = ABACWatcher(watch_dirs)
    w.run()
