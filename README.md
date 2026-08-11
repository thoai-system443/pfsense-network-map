# pfSense Network Map

Đọc file backup `config.xml` của pfSense và trả lời câu hỏi mà bảng rule không
trả lời được: **ai thực sự tới được đâu, trên cổng nào, và bị chặn ở đâu.**

Nạp được nhiều firewall cùng lúc để đi hết đường mà packet phải qua. Chạy hoàn
toàn offline, không gọi ra internet lúc nào.

---

## Chạy

Hai stack độc lập, mỗi cái một `docker-compose.yml`:

```bash
cd backend && cp .env.example .env && docker compose up -d --build
```

```bash
cd frontend && cp .env.example .env && docker compose up -d --build
```

Mở <http://localhost:8011>. Backend ở `:8010`.

Đổi port hoặc địa chỉ backend thì sửa `.env` rồi `docker compose up -d` — **không
cần build lại**, `API_URL` được đọc lúc container khởi động.

> `docker compose restart` **không** nạp lại biến môi trường. Luôn dùng `up -d`.

## Nạp dữ liệu

Trên trang đầu, chọn `config.xml` của firewall thứ nhất. Nếu mạng có nhiều
firewall, chọn tiếp file của những cái còn lại — chúng vào cùng một workspace và
được phân tích như một hệ thống. Bấm **Open the map** khi xong.

**Việc đầu tiên nên làm: đọc danh sách cảnh báo.** Parser báo cáo mọi field nó
không nhận ra thay vì im lặng bỏ qua. Danh sách rỗng nghĩa là nó hiểu trọn file;
không rỗng nghĩa là kết quả có thể thiếu, và cảnh báo chỉ đúng chỗ nào.

## Năm màn hình

| | Trả lời |
|---|---|
| **Topology** | Mạng trông như thế nào — interface, VLAN, tunnel, và subnet mà nhiều firewall cùng đấu vào |
| **Access map** | Zone nào tới được zone nào, trên cổng nào. Kéo node để gỡ rối, click để lọc, chuột phải để ẩn |
| **Search** | Bốn kiểu tra cứu, xem bên dưới |
| **Inventory** | Liệt kê và lọc interface, alias, rule, NAT theo IP / network / port |
| **Risk** | Object nào lộ ra ngoài, ai tới được một cổng, và rule deny-all nào không chặn thật |

### Bốn kiểu tra cứu

- **Across firewalls** — `A → B:port` đi hết chuỗi firewall. `pass` chỉ khi **mọi**
  chặng cho qua; chặng đầu tiên từ chối là chặng được báo, kèm firewall, interface
  và rule cụ thể.
- **Path check** — như trên nhưng chỉ trên **một** firewall, kèm trace đầy đủ các
  rule đã xét. Hữu ích khi muốn soi riêng một bộ rule.
- **From** — một nguồn đi được tới đâu. Kết quả là phân hoạch **đầy đủ** của toàn
  bộ không gian (địa chỉ × cổng), không phải liệt kê mẫu.
- **To** — ai tới được một đích, nhóm theo interface vào.

Mọi ô nhập nhận IP, CIDR, tên alias, hoặc tên interface.

---

## Điều quan trọng nhất cần biết

Công cụ này mô phỏng `pf`, và chỗ dễ mô phỏng sai nhất đã được xử lý tường minh:

- **Floating rule mặc định không `quick`**, interface rule thì có. Một floating
  rule khớp vẫn có thể bị interface rule đứng sau ghi đè. Coi là first-match-wins
  sẽ cho kết quả sai.
- **Action `match` không quyết định gì.** Nó gắn queue rồi để đánh giá đi tiếp.
  Coi nó là `block` biến một floating shaper rule thành tường chặn cả interface.
- **NAT đích áp trước khi lọc.** Rule cho phép phải trỏ tới IP nội bộ đã dịch,
  không phải IP public.
- **Rule của tunnel VPN nằm trên pseudo-interface** `openvpn` / `enc0`, không phải
  trên một interface được cấu hình.

`explore_from` và `check` là hai đường tính khác nhau cho cùng ngữ nghĩa, và có
test chốt rằng chúng **luôn** cho cùng kết quả.

## Giới hạn, nói trước

- **Parser viết theo schema pfSense 2.7 và chưa được kiểm chứng đầy đủ.** Sáu
  field đã được bổ sung từ config thật (`srcmac`, `dstmac`, `bridgeto`, `match`,
  `source_hash_key`, `ipprotocol`). Còn thiếu gì nữa thì danh sách cảnh báo sẽ
  chỉ ra.
- **Chuỗi firewall dừng khi next-hop thuộc thiết bị không được nạp.** Giao diện
  báo rõ là đã dừng và dừng ở đâu. Nó **không** kết luận "thông" cho phần chưa
  kiểm.
- **Không mô phỏng state table hay reply traffic.** Mọi đánh giá là cho packet
  đầu tiên của một kết nối.
- **`srcmac` / `dstmac` / `bridgeto` không được mô phỏng.** Rule dùng chúng khớp
  ít packet hơn thực tế, nên kết quả liên quan có thể **rộng hơn** thực tế. Parser
  cảnh báo mỗi khi gặp.
- **Outbound NAT không ảnh hưởng verdict** — chỉ hiển thị để tham khảo.
- **Không có database.** Config nằm trong RAM tiến trình backend; restart là mất,
  phải nạp lại. Vì vậy backend chỉ chạy **một** worker uvicorn.

---

## Kiến trúc

```
backend/            FastAPI, không database, nginx là port duy nhất publish
  app/parser/       chỉ hiểu XML, cho ra kiểu dữ liệu thuần
  app/engine/       chỉ làm việc trên kiểu dữ liệu đó, không bao giờ chạm XML
  app/api/          ghép hai tầng kia với HTTP
frontend/           Vite + React + TypeScript, build ra dist/ tĩnh
```

Ranh giới parser ↔ engine cho phép test engine bằng object dựng tay, không cần
file XML.

### API

Tất cả dưới `/api/v1`. Tài liệu tương tác ở `/api/v1/docs` (HTTP Basic auth,
đặt `DOCS_USER` / `DOCS_PASSWORD` trong `.env`).

| Method | Path |
|---|---|
| `POST` | `/configs` |
| `POST` | `/configs/{id}/firewalls` |
| `GET` `DELETE` | `/configs/{id}` |
| `GET` | `/configs/{id}/interfaces` `/aliases` `/rules` `/nat` |
| `GET` | `/configs/{id}/topology` `/access-graph` |
| `POST` | `/configs/{id}/query/path` `/check` `/from` `/to` |
| `GET` | `/configs/{id}/risk` `/risk/port` |

## Phát triển

```bash
cd backend
python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest && .venv/bin/ruff check app tests
```

```bash
cd frontend
npm install && npm run test && npm run lint
```

Hoặc chạy test backend trong container: `cd backend && ./test.sh`.

Chi tiết kiến trúc, quy ước và những cạm bẫy đã gặp nằm trong
[BACKEND_GUIDE.md](BACKEND_GUIDE.md) và [FRONTEND_GUIDE.md](FRONTEND_GUIDE.md).
Thiết kế ban đầu và kế hoạch triển khai ở [docs/superpowers/](docs/superpowers/).

## Offline

Không CDN font, không map tile, không gọi mạng ngoài lúc chạy. Alias loại `url`
và `urltable` **không** được fetch — chúng cho tập rỗng và kết quả liên quan được
đánh dấu `unresolved`.

Sau khi kéo image một lần, toàn bộ hệ thống chạy được trong môi trường air-gapped.
