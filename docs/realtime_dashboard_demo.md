# Realtime dashboard demo cho EDR lab

Tài liệu này mô tả demo near-realtime an toàn cho flow:

```text
Sysmon Event Log
  -> realtime collector
  -> normalize event
  -> rule detection / behavioral correlation
  -> alert
  -> dashboard API
  -> dashboard UI auto update
  -> Elasticsearch indices
  -> Kibana Discover
```

Đây là demo research/lab, không phải production EDR agent. Collector chỉ đọc event mới từ lúc script start.

## 1. Chạy Docker trên host

Trên host machine:

```powershell
cd D:\Learning\Security\EDR
.\scripts\setup\use_host_docker.ps1 192.168.213.1
docker compose up -d
docker compose -f docker-compose.kafka.yml up -d
```

`use_host_docker.ps1` set các env như:

```text
EDR_DOCKER_HOST=192.168.213.1
EDR_ELASTICSEARCH_URL=http://192.168.213.1:9200
```

Kiểm tra Elasticsearch/Kibana:

```powershell
Invoke-RestMethod http://192.168.213.1:9200
```

```text
Kibana: http://192.168.213.1:5601
```

## 2. Chạy realtime collector/API trong Windows VM

Terminal 1 trong VM:

```powershell
cd C:\Project\EDR
git pull
.\.venv\Scripts\Activate.ps1
.\scripts\setup\use_host_docker.ps1 192.168.213.1
python scripts\realtime\run_realtime_dashboard.py --port 8090 --poll-interval 2 --elastic-url http://192.168.213.1:9200
```

Nếu không truyền `--elastic-url`, script đọc env:

```text
EDR_ELASTICSEARCH_URL
```

API endpoints:

```text
GET /api/health
GET /api/events
GET /api/alerts
GET /api/summary
GET /api/stream
```

Health check:

```powershell
Invoke-RestMethod http://localhost:8090/api/health
```

Kết quả có dạng:

```json
{
  "status": "ok",
  "collector": "running",
  "elasticsearch": "connected",
  "event_count": 0,
  "alert_count": 0
}
```

Nếu Elasticsearch tắt hoặc không reachable, API vẫn chạy local. `/api/health` sẽ báo `elasticsearch: disconnected` và terminal có warning.

## 3. Chạy dashboard static

Terminal 2 trong VM:

```powershell
cd C:\Project\EDR
python -m http.server 8088 -d dashboard/static
```

Mở:

```text
http://localhost:8088
```

Dashboard poll API realtime mỗi 2 giây:

```text
http://localhost:8090/api/summary
http://localhost:8090/api/events
http://localhost:8090/api/alerts
```

Nếu API online, UI hiển thị:

```text
Realtime: connected
```

Nếu API offline, UI vẫn dùng static fallback:

```text
dashboard/static/data/realtime_events.json
dashboard/static/data/realtime_alerts.json
dashboard/static/data/realtime_summary.json
```

## 4. Chạy safe simulation

Terminal 3 trong VM:

```powershell
cd C:\Project\EDR
.\scripts\realtime\run_safe_simulation.ps1
```

Script chỉ tạo telemetry an toàn:

- `T1059.001`: `powershell.exe -NoProfile -ExecutionPolicy Bypass`
- `T1105`: `curl.exe` tải file từ `http://127.0.0.1:8080`
- `T1547.001`: add/delete `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `T1218-lite`: `rundll32.exe url.dll,FileProtocolHandler`

Không tải internet, không tắt Defender, không chạy malware/payload nguy hiểm.

Output kỳ vọng:

```text
[OK] Triggered T1059.001
[OK] Triggered T1105
[OK] Triggered T1547.001
[OK] Triggered T1218-lite
[OK] Triggered benign cmd TN marker
[OK] Triggered benign PowerShell TN marker
```

## 5. Realtime Evaluation Mode

Dashboard có thêm panel `Realtime Evaluation` để tính TP/TN/FP/FN live từ marker deterministic:

```text
EDR_DEMO_T1059_001       -> expected alert -> TP nếu rule T1059.001 fire
EDR_DEMO_T1105           -> expected alert -> TP nếu rule T1105 fire
EDR_DEMO_T1547           -> expected alert -> TP nếu rule T1547.001 fire
EDR_DEMO_T1218           -> expected alert -> TP nếu rule T1218-lite fire
EDR_BENIGN_CMD           -> expected no alert -> TN nếu không có alert sau window
EDR_BENIGN_POWERSHELL    -> expected no alert -> TN nếu không có alert sau window
```

TP có thể xuất hiện gần như ngay khi alert được tạo. TN cần đợi evaluation window ngắn, mặc định 6 giây cho benign markers, vì hệ thống phải chắc rằng không có alert nào xuất hiện.

API:

```text
GET /api/evaluation
```

Static fallback:

```text
dashboard/static/data/realtime_evaluation.json
```

Trade-off: đây là live evaluation cho demo marker, không phải ground-truth engine production. Trong production, ground truth phải đến từ test manifest, campaign runner, hoặc labeling pipeline.

## 6. Detection realtime

Collector theo dõi Sysmon log:

```text
Microsoft-Windows-Sysmon/Operational
```

Event ID hỗ trợ:

- `1` Process Create
- `3` Network Connection
- `11` File Create
- `13` Registry Value Set

Rule realtime-native:

- `det.realtime.t1059_001.powershell_execution`
- `det.realtime.t1105.ingress_tool_transfer`
- `det.realtime.t1547_001.registry_run_key`
- `det.realtime.t1218_lite.rundll32_url_handler`

Behavioral correlation:

- `behavioral.realtime.t1105.process_network_file`
- Window 5 phút
- Cần chuỗi process create + network connection + file create cùng process/image hoặc marker `EDR_DEMO_T1105`

## 7. Elasticsearch indices

Realtime events được index vào:

```text
edr-realtime-events-YYYY.MM.DD
```

Realtime alerts được index vào:

```text
edr-realtime-alerts-YYYY.MM.DD
```

Ví dụ:

```text
edr-realtime-events-2026.06.21
edr-realtime-alerts-2026.06.21
```

Các index cũ vẫn giữ nguyên, không bị xóa hoặc thay đổi:

```text
edr-normalized-events-*
edr-alerts-native-*
```

## 8. Tạo Kibana Data Views

Trong Kibana:

```text
Stack Management -> Data Views -> Create data view
```

Tạo các data view chính:

```text
edr-realtime-events-*
edr-realtime-alerts-*
```

Fallback/compatibility nếu cần xem pipeline cũ:

```text
edr-normalized-events-*
edr-alerts-native-*
```

Discover search:

```text
EDR_DEMO
```

Hoặc với alert:

```text
rule.id: *
```

## 9. Demo với giảng viên

Trình tự demo:

1. Start Docker Elasticsearch/Kibana trên host.
2. Start realtime collector/API trong VM.
3. Start dashboard static.
4. Mở `http://localhost:8088`, xác nhận `Realtime: connected`.
5. Chạy `.\scripts\realtime\run_safe_simulation.ps1`.
6. Trong 2-5 giây, dashboard xuất hiện Realtime Alerts và Realtime Events.
7. Trong khoảng 6-8 giây, `Realtime Evaluation` cập nhật TP/TN/FP/FN live.
8. Mở Kibana Discover với `edr-realtime-events-*`, search `EDR_DEMO`.
9. Mở Kibana Discover với `edr-realtime-alerts-*`, search `rule.id: *`.

Giải thích ngắn:

- Sysmon chỉ ghi telemetry như process, network, file, registry.
- Sysmon không biết ATT&CK technique.
- Technique như `T1059.001` hoặc `T1105` do rule gán khi match behavior.
- Dashboard là view/operator UI.
- Kibana là backend evidence để chứng minh event/alert đã được index.
- Đây là near-realtime demo, chưa phải production EDR agent.

## 10. Local audit output

Collector luôn ghi file local để debug/audit:

```text
reports/realtime/events.jsonl
reports/realtime/alerts.jsonl
dashboard/static/data/realtime_events.json
dashboard/static/data/realtime_alerts.json
dashboard/static/data/realtime_evaluation.json
dashboard/static/data/realtime_summary.json
```

Giới hạn memory:

```text
events: 500 latest
alerts: 200 latest
```

## 11. Troubleshooting

Nếu dashboard disconnected:

```powershell
Invoke-RestMethod http://localhost:8090/api/health
```

Nếu collector không đọc được Sysmon:

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 1
```

Nếu Elasticsearch disconnected:

```powershell
Invoke-RestMethod http://192.168.213.1:9200
```

Nếu chưa thấy event/alert:

- Start collector trước khi chạy simulation.
- Đợi 2-5 giây vì dashboard polling mỗi 2 giây.
- Kiểm tra `reports/realtime/events.jsonl`.
- Kiểm tra `reports/realtime/alerts.jsonl`.
- Search `EDR_DEMO` hoặc `EDR_BENIGN` trong Kibana Discover.

## 12. Limitations

- Polling `Get-WinEvent`, không phải kernel driver/agent production.
- Store realtime là in-memory, chỉ giữ window mới nhất.
- Correlation T1105 là demo heuristic, chưa production-perfect.
- TP/TN/FP/FN realtime phụ thuộc vào demo markers và evaluation window.
- Không có auth cho local API.
- Elasticsearch indexing là best-effort: fail thì log warning và dashboard vẫn chạy local.
