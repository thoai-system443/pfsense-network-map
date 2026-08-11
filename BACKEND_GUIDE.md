# Backend Guide

| Version | Date | Changes |
|---|---|---|
| 1.2.0 | 2026-08-10 | `CORS_ORIGINS` nhận chuỗi thô và danh sách phẩy, có kiểm tra định dạng |
| 1.1.0 | 2026-08-10 | Nhận diện `srcmac`/`dstmac`/`bridgeto` từ config thật đầu tiên, kèm cảnh báo "không mô phỏng" |
| 1.0.0 | 2026-08-10 | Kiến trúc ban đầu: parser, engine, API stateless |

## Stack

Python 3.12, FastAPI, pydantic v2, pydantic-settings, uvicorn (một worker),
nginx, Docker Compose. **Không có database.** pytest và ruff cho test và lint.

## Bố cục

```
app/parser/   chỉ hiểu XML, cho ra kiểu dữ liệu trong app/parser/types.py
app/engine/   chỉ làm việc trên kiểu dữ liệu đó, không bao giờ chạm XML
app/api/      ghép hai tầng kia với HTTP
```

Ranh giới này cho phép test engine bằng object dựng tay, không cần file XML.
`app/parser/xmlutil.py` giữ các helper XML dùng chung, tách khỏi `loader.py` để
các parser con không phải import vòng qua loader.

## Chạy và test

```
cp .env.example .env
docker compose up -d --build
./test.sh                     # pytest trong container api
```

Phát triển nhanh hơn thì dùng venv cục bộ:

```
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check app tests
```

nginx là container duy nhất publish port. uvicorn không bind ra host.

## Biến môi trường

| Tên | Bắt buộc | Mô tả |
|---|---|---|
| `API_PORT` | không | Port host cho nginx, mặc định **8010** |
| `DOCS_USER` | **có** | Tài khoản Basic auth cho `/api/v1/docs` |
| `DOCS_PASSWORD` | **có** | Mật khẩu Basic auth. Entrypoint fail fast nếu thiếu |
| `CORS_ORIGINS` | không | Origin được phép, mặc định `http://localhost:8011`. Xem bên dưới |

### CORS_ORIGINS

Nhận ba cách viết, kết quả như nhau:

```
CORS_ORIGINS=http://localhost:8011
CORS_ORIGINS=http://localhost:8011, https://map.example.com
CORS_ORIGINS=["http://localhost:8011"]
```

Mỗi giá trị phải là `scheme://host[:port]`. Dấu `/` cuối bị bỏ; có đường dẫn hoặc
thiếu scheme thì bị từ chối kèm thông báo nêu đúng giá trị sai. `*` được giữ
nguyên. Trình duyệt gửi header `Origin` không có đường dẫn và không có `/` cuối,
nên một giá trị lưu sai định dạng sẽ **không bao giờ khớp** — chặn sớm lúc khởi
động dễ chẩn đoán hơn nhiều so với lỗi CORS mơ hồ trên trình duyệt.

`Annotated[list[str], NoDecode]` trong `app/settings.py` là bắt buộc, không phải
trang trí: thiếu nó, pydantic-settings JSON-decode giá trị env ngay trong settings
source, **trước** khi validator chạy, và mọi cách viết không phải JSON đều chết ở
đó bằng `SettingsError`. Test phải đi qua biến môi trường thật
(`monkeypatch.setenv`) — dựng `Settings(...)` bằng constructor đi đường khác và
bỏ qua đúng tầng gây lỗi.

## Ngữ nghĩa đánh giá rule

Đây là phần lõi, và là chỗ dễ mô phỏng sai nhất.

1. Xác định interface vào từ IP nguồn — mạng khớp prefix dài nhất. Danh sách ứng
   viên gồm **cả subnet của interface lẫn dải mạng của tunnel VPN**, vì pfSense
   gắn rule của tunnel vào pseudo-interface `openvpn` / `enc0` chứ không phải một
   interface được cấu hình. Không có mạng nào khớp thì rơi về `wan`.
2. Ruleset = floating rules (khớp interface, direction `in`/`any`) → rule của
   chính interface → implicit anti-lockout rule trên LAN. Rule `disabled` bị loại
   ngay từ bước dựng.
3. Duyệt tuần tự, giữ `last_match`: rule khớp **và** `quick` thì trả ngay; rule
   khớp nhưng không `quick` thì ghi lại rồi đi tiếp. Hết ruleset mà chưa từng
   khớp thì **default deny**.
4. NAT đích (port forward, 1:1) áp **trước** khi lọc. Rule cho phép phải trỏ tới
   IP nội bộ đã dịch, không phải IP public.

`explore_from` / `explore_to` chạy đúng luật trên nhưng trên toàn bộ không gian
(địa chỉ × port) bằng phép trừ tập hai chiều, nên kết quả đầy đủ chứ không phải
liệt kê mẫu. Test `test_explore_agrees_with_point_check_on_sampled_points` chốt
rằng hai đường tính này luôn cho cùng kết quả.

## Quy ước

- Route chữ cố định khai báo trước route `/{id}` cùng cấp.
- Dependency dùng `Annotated[T, Depends(...)]` (`ConfigDep` trong
  `app/api/v1/configs.py`), không gọi `Depends()` trong default argument — ruff
  B008 bắt đúng chỗ đó.
- Parser không im lặng bỏ qua field lạ: mọi phần tử không nhận diện được sinh một
  `ParseWarning` và đi lên tận response upload.
- IPv4 và IPv6 nằm trong hai không gian tách biệt. Mọi phép toán trộn hai họ đều
  ném lỗi.
- Alias `url` và `urltable` không được fetch. Chúng cho tập rỗng và đánh dấu kết
  quả là `unresolved`.
- `PortSet.to_spec()` và `PortSet.parse()` round-trip được, kể cả `"any"` và
  `"none"`.

## Gotchas

- **`docker compose restart` không nạp lại env.** Dùng `up -d` để tạo lại container.
- **Chỉ chạy một worker uvicorn.** Store nằm trong RAM tiến trình; nhiều worker sẽ
  khiến request rơi vào process không giữ config.
- **Compose project name phải đặt tường minh** (`name:` trong `docker-compose.yml`).
  Mặc định Compose lấy tên thư mục — ở đây là `backend`, quá chung. Máy dev này
  đã có một project khác cũng nằm trong thư mục `backend`; container của nó bị
  coi là orphan của project này và **`docker compose down --remove-orphans` sẽ
  xoá mất**. Đừng bỏ dòng `name:`, và đừng chạy `--remove-orphans` ở đây.
- **`nginx:alpine` không có `openssl`.** Image nginx được build từ
  `nginx/Dockerfile` để cài lúc build, giữ runtime air-gapped.
- **`set -e` không bắt command substitution hỏng nằm trong tham số `printf`.**
  Entrypoint vì vậy kiểm tra hash tường minh; bản đầu tiên ghi ra `.htpasswd` cụt
  và trả 401 cho mọi request mà không báo lỗi gì.
- **Floating rule mặc định không `quick`, interface rule thì có.** Đây là lý do
  một floating rule khớp vẫn có thể bị interface rule đứng sau ghi đè. Đừng "sửa"
  thành first-match-wins.
- **Outbound NAT không ảnh hưởng verdict** và không được đưa vào engine đánh giá.
- Tập địa chỉ được chuẩn hoá: `to_cidrs()` trả vùng phủ CIDR tối thiểu, nên hai
  host liền kề `.10` và `.11` hiện ra thành `.10/31` chứ không phải hai `/32`.

## Field thu hẹp rule mà engine không mô phỏng

Một rule có thể khớp **ít** packet hơn phần địa chỉ và port gợi ý. Engine bỏ qua
những field đó, nên mọi verdict rút ra từ rule như vậy chỉ có thể **rộng hơn**
thực tế, không bao giờ chặt hơn. Danh sách nằm ở `NARROWING_FIELDS` trong
`app/parser/rules.py`; mỗi lần gặp, parser sinh một `ParseWarning` nói rõ điều đó.

| Field | Thu hẹp theo |
|---|---|
| `srcmac` | Địa chỉ MAC nguồn |
| `dstmac` | Địa chỉ MAC đích |
| `bridgeto` | Interface thành viên bridge |

Gặp field thu hẹp mới trong config thật thì thêm vào **cả hai**:
`KNOWN_RULE_CHILDREN` (để hết báo "unrecognised") và `NARROWING_FIELDS` (để vẫn
cảnh báo). Chỉ thêm vào danh sách thứ nhất là biến một giới hạn đã biết thành một
lỗi im lặng.

## Chưa kiểm chứng

Parser viết theo schema pfSense 2.7. Lần đối chiếu đầu tiên với config thật đã
phát hiện ba field thiếu (`srcmac`, `dstmac`, `bridgeto`) — cơ chế `ParseWarning`
hoạt động đúng như thiết kế. Vẫn còn hai chỗ rủi ro:

1. **Tên field** trong các hằng `KNOWN_*_CHILDREN` của từng module parser. Danh
   sách `warnings` trong response upload sẽ chỉ ra ngay chỗ thiếu — đó là lý do
   cơ chế cảnh báo tồn tại. Xem `warnings` trước khi tin kết quả.
2. **Interface group.** `ruleset.build` xử lý group bằng cách so tên group với
   tên interface, nhưng chưa có fixture vì chưa biết cấu trúc `<ifgroups>` thật.

## Ngoài phạm vi

Không đọc gateway và static route, nên subnet nằm sau router nội bộ sẽ không lên
bản đồ. Không có khái niệm user. Không traffic shaper. Không mô phỏng state table
hay reply traffic. Không so sánh hai bản backup.
