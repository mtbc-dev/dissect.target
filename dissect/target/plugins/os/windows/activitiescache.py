from __future__ import annotations

from typing import TYPE_CHECKING, Any, Mapping
import json
from importlib import resources

from dissect.sql import sqlite3
from dissect.util.ts import from_unix

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
import re
if TYPE_CHECKING:
    from collections.abc import Iterator
    from datetime import datetime
    from dissect.target.target import Target

ActivitiesCacheRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/activitiescache",
    [
        ("datetime", "timestamp"),              
        ("string", "timestamp_type"),
        ("string", "action"),
        ("boolean", "is_deleted"),
        ("uint32", "focus_time_sec"),
        ("string", "clipboard_text"),
        ("string", "file_name"),
        ("string", "executable_path"),
        ("string", "raw_guid"),
        ("datetime", "start_time"),
        ("datetime", "end_time"),
        ("datetime", "last_modified_time"),
        ("datetime", "last_modified_on_client"),
        ("datetime", "original_last_modified_on_client"),
        ("datetime", "expiration_time"),
        ("string", "activity_id"),
        ("string", "app_id"),
        ("string", "enterprise_id"),
        ("string", "app_activity_id"),
        ("string", "group_app_activity_id"),
        ("string", "group"),
        ("uint32", "activity_type"),
        ("uint32", "activity_status"),
        ("uint32", "activity_priority"),
        ("uint32", "match_id"),
        ("uint32", "etag"),
        ("string", "tag"),
        ("boolean", "is_local_only"),
        ("datetime", "created_in_cloud"),
        ("string", "platform_device_id"),
        ("string", "package_id_hash"),
        ("string", "payload"),
        ("string", "original_payload"),
        ("string", "clipboard_payload"),
        ("path", "source"),
    ],
)


def load_guid_mapping() -> Mapping[str, str]:
    """Read guidlist.txt and return a {GUID → alias} dictionary; empty dict if the file is missing."""
    try:
        path = resources.files("dissect.target.helpers.data").joinpath("guidlist.txt")
        with path.open(encoding="utf-8") as f:
            return {
                l.split(",", 1)[0].strip().upper(): l.split(",", 1)[1].strip()
                for l in f
                if "," in l
            }
    except FileNotFoundError:
        return {}

_GUIDS = load_guid_mapping()

def first_application(x: Any) -> str:
    """If *x* is a JSON array produced by Windows Timeline, return the first element’s 'application' field; otherwise an empty string."""
    if not x:
        return ""
    if isinstance(x, (bytes, bytearray)):
        x = x.decode("utf-8", errors="ignore")
    try:
        d = json.loads(x)
        if isinstance(d, list) and d:
            return str(d[0].get("application", ""))
    except Exception:
        pass
    return ""

def _normalize_package_name(raw: str | None) -> str:
    """Replace GUIDs when known in *raw* with human‑readable aliases from the mapping, case‑insensitive, and strip braces."""
    if not raw:
        return ""
    s = str(raw)
    def _repl(match: re.Match[str]) -> str:            
        guid = match.group(1).upper()                 
        return _GUIDS.get(guid, guid)   
    return re.sub(
            r"\{?([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\}?",
            _repl,
            str(raw),
            flags=re.I,
        ).replace("{", "").replace("}", "")


def filename_from_payload(raw: Any | None) -> str:
    """Decode *raw* and, if it looks like JSON, return its 'displayText'; otherwise return the raw string."""
    if not raw:
        return ""
    payload = raw.decode("utf-8", errors="ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
    pl = payload.lstrip()
    if pl.startswith("{"):
        try:
            return str(json.loads(pl).get("displayText", payload))
        except Exception:
            pass
    return payload

class ActivitiesCachePlugin(Plugin):
    """Plugin that parses the ActivitiesCache.db on newer Windows 10 machines.

    References:
        - https://www.cclsolutionsgroup.com/resources/technical-papers
        - https://salt4n6.com/2018/05/03/windows-10-timeline-forensic-artefacts/
    """

    def __init__(self, target: Target):
        super().__init__(target)
        self.cachefiles = []

        for user_details in target.user_details.all_with_home():
            full_path = user_details.home_path.joinpath("AppData/Local/ConnectedDevicesPlatform")
            cache_files = full_path.glob("*/ActivitiesCache.db")
            for cache_file in cache_files:
                if cache_file.exists():
                    self.cachefiles.append((user_details.user, cache_file))


    def check_compatible(self) -> None: 
        if not self.cachefiles:
            raise UnsupportedPluginError("No ActiviesCache.db files found")

    @export(record=ActivitiesCacheRecord)
    def activitiescache(self) -> Iterator[ActivitiesCacheRecord]:  
        """Return ActivitiesCache.db database content.

        The Windows Activities Cache database keeps track of activity on a device, such as application and services
        usage, files opened, and websites browsed. This database file can therefore be used to create a system timeline.
        It has first been used on Windows 10 1803.
        Parse the Activity table, keep only ActivityTypes 5, 6, 10, 16:
        - timestamp = LastModifiedTime
        - computes focus_time_sec for type 6
        - fills clipboard_text from GroupVal for type 16
        - maps executables, GUIDs, filenames, deletion flag, etc.

        References:
            - https://artifacts-kb.readthedocs.io/en/latest/sources/windows/ActivitiesCacheDatabase.html
            - https://salt4n6.com/2018/05/03/windows-10-timeline-forensic-artefacts/

        Yields ActivitiesCacheRecords with the following fields:

        .. code-block:: text

            hostname (string): The target hostname.
            domain (string): The target domain.
            timestamp (datetime): Main timeline timestamp (LastModifiedOnClient).
            timestamp_type (string): Constant "LastModifiedOnClient" for this plugin version.
            action (string): "Open" (type 5), "" (type 6), "ClipboardData" (type 10) or "Clipboard" (type 16).
            is_deleted (boolean): True if ActivityStatus == 3.
            focus_time_sec (uint32): Focus duration in seconds for ActivityType 6; otherwise None.
            clipboard_text (string): Raw GroupVal for type 16; empty otherwise.
            file_name (string): displayText from Payload for type 5; empty for other types.
            executable_path (string): Human‑readable executable path with GUIDs resolved.
            raw_guid (string): Original GUID part of AppActivityId or first application GUID from AppId.
            start_time (datetime): StartTime field.
            end_time (datetime): EndTime field.
            last_modified_time (datetime): LastModifiedTime field.
            last_modified_on_client (datetime): LastModifiedOnClient field.
            original_last_modified_on_client (datetime): OriginalLastModifiedOnClient field.
            expiration_time (datetime): ExpirationTime field.
            activity_id (string): Id field in hex.
            app_id (string): AppId field, JSON string containing multiple types of app name definitions.
            enterprise_id (string): EnterpriseId field.
            app_activity_id (string): AppActivityId field.
            group_app_activity_id (string): GroupAppActivityId field.
            group (string): Group field.
            activity_type (int): ActivityType field.
            activity_status (int): ActivityStatus field.
            activity_priority (int): Priority field.
            match_id (int): MatchId field.
            etag (int): ETag field.
            tag (string): Tag field.
            is_local_only (boolean): IsLocalOnly field.
            created_in_cloud (datetime): CreatedInCloud field.
            platform_device_id (string): PlatformDeviceId field.
            package_id_hash (string): PackageIdHash field.
            payload (string): Payload field. JSON string containing payload data, varies per type.
            original_payload (string): OriginalPayload field.
            clipboard_payload (string): ClipboardPayload field.
        """
        for user, cache_file in self.cachefiles:
            db = sqlite3.SQLite3(cache_file.open())
            act = db.table("Activity")
            if act is None:
                continue

            for r in act.rows():
                t = r["[ActivityType]"]
                if t not in (5, 6, 10, 16):
                    continue

                lmoc = r["[LastModifiedOnClient]"]
                if lmoc in (None, 0, "0"):
                    continue

                base_action = {5: "Open", 6: "FocusEnd", 10: "ClipboardData", 16: "Clipboard"}[t]
                is_deleted = str(r["[ActivityStatus]"]).strip() == "3"


                raw_app_activity = r["[AppActivityId]"] or ""
                parts = str(raw_app_activity).split("\\", 1)
                if len(parts) > 1:
                    guid, exe = parts
                else:
                    exe = _normalize_package_name(first_application(r["[AppId]"]))
                    guid = first_application(r["[AppId]"])


                file_name = filename_from_payload(r["[Payload]"]) if t == 5 else ""
                clipboard_text = str(r["[GroupVal]"]) if t == 16 and r["[GroupVal]"] else ""

                focus_sec = None
                if t == 6:
                    st_val, et_val = r["[StartTime]"], r["[EndTime]"]
                    try:
                        if st_val and et_val and int(st_val) and int(et_val):
                            focus_sec = int(et_val) - int(st_val)
                    except Exception:
                        pass

                yield ActivitiesCacheRecord(
                    timestamp=mkts(r["[LastModifiedTime]"]),
                    timestamp_type="LastModifiedTime",
                    action=base_action,
                    activity_type=t,
                    is_deleted=is_deleted,
                    focus_time_sec=focus_sec,
                    clipboard_text=clipboard_text,
                    file_name=file_name,
                    executable_path=exe,
                    raw_guid=guid,
                    _target=self.target,
                    _user=user,
                    start_time=mkts(r["[StartTime]"]),
                    end_time=mkts(r["[EndTime]"]),
                    last_modified_time=mkts(r["[LastModifiedTime]"]),
                    last_modified_on_client=mkts(r["[LastModifiedOnClient]"]),
                    original_last_modified_on_client=mkts(r["[OriginalLastModifiedOnClient]"]),
                    expiration_time=mkts(r["[ExpirationTime]"]),
                    activity_id=r["[Id]"].hex(),
                    app_id=r["[AppId]"],
                    app_activity_id=raw_app_activity,
                    group=r["[Group]"] or None,
                    activity_status=r["[ActivityStatus]"],
                    activity_priority=r["[Priority]"],
                    match_id=r["[MatchId]"],
                    etag=r["[ETag]"],
                    is_local_only=r["[IsLocalOnly]"],
                    created_in_cloud=r["[CreatedInCloud]"],
                    platform_device_id=r["[PlatformDeviceId]"],
                    package_id_hash=r["[PackageIdHash]"],
                    payload=r["[Payload]"],
                    original_payload=r["[OriginalPayload]"],
                    clipboard_payload=r["[ClipboardPayload]"],
                    source=cache_file,
                )



def mkts(ts: int | None) -> datetime | None:
    """Convert a Unix epoch (seconds) to Python datetime in UTC, or None if the timestamp is zero/None."""
    return from_unix(ts) if ts else None
