from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from dissect.target.plugins.os.windows.activitiescache import ActivitiesCachePlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_windows_activitiescache_10_22H2(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we can parse an ActivitiesCache.db file from Windows 10 22H2 correctly."""
    fs_win.map_file(
        "Users/John/AppData/Local/ConnectedDevicesPlatform/L.John/ActivitiesCache.db",
        str(absolute_path("_data/plugins/os/windows/activitiescache/ActivitiesCache.db")),
    )

    target_win_users.add_plugin(ActivitiesCachePlugin)

    records = list(target_win_users.activitiescache())
    assert len(records) == 9
    assert records[6].activity_type == 16
    assert records[6].clipboard_type == "Copy"
    assert records[2].action == "FocusEnd"
    assert records[2].is_deleted == False
    assert records[2].focus_time_sec == 14
    assert records[2].executable_path == "{ThisPCDesktopFolder}\\filetest.txt"
    assert records[3].file_name == "filetest.txt"
    assert records[2].timestamp == datetime(2025, 7, 22, 14, 56, 23, tzinfo=timezone.utc)
    assert records[2].start_time == datetime(2025, 7, 22, 14, 56, 9, tzinfo=timezone.utc)
    assert records[2].end_time == datetime(2025, 7, 22, 14, 56, 23, tzinfo=timezone.utc)
    assert records[2].last_modified_time == datetime(2025, 7, 22, 14, 56, 23, tzinfo=timezone.utc)
    assert records[2].last_modified_on_client == datetime(2025, 7, 22, 14, 56, 23, tzinfo=timezone.utc)
    assert not records[0].original_last_modified_on_client
    assert records[2].expiration_time == datetime(2025, 8, 21, 14, 56, 23, tzinfo=timezone.utc)
    assert records[2].activity_id == "20a63c839f571895994e4ba205856229"
    assert (
        records[2].app_id
        == '[{"application":"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\\\notepad.exe","platform":"windows_win32"},{"application":"{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}\\\\notepad.exe","platform":"windows_win32"},{"application":"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\\\notepad.exe","platform":"packageId"},{"application":"","platform":"alternateId"}]' 
    )
    assert not records[2].enterprise_id
    assert (
        records[0].app_activity_id
        == "ECB32AF3-1440-4086-94E3-5311F97F89C4"
    )
    assert records[2].activity_type == 6
    assert records[2].activity_status == 1
    assert records[2].activity_priority == 1
    assert not records[2].match_id
    assert records[2].etag == 6
    assert records[2].is_local_only == False
    assert records[2].platform_device_id == "Vwyqm9v6lmHzuRWh9Y5giQO0QaWDLu5Ustb9uwou4/I="
    assert records[2].package_id_hash == "eUssiHYOx8gt4grLn60pEG2m1QnscYA3695n7jpHJwY="
    assert records[2].payload == '{"type":"UserEngaged","reportingApp":"ShellActivityMonitor","activeDurationSeconds":14,"shellContentDescription":{"MergedGap":600,"ActivityEngagementFlags":3},"userTimezone":"Europe/Paris"}'
    assert not records[2].original_payload
    assert not records[2].clipboard_payload
    assert records[2].source == "C:\\Users\\John\\AppData\\Local\\ConnectedDevicesPlatform\\L.John\\ActivitiesCache.db"
    assert records[2].username == "John"
