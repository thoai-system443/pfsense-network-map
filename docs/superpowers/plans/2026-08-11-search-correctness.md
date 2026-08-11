# Sửa độ chính xác của Search — kế hoạch

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or
> superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Bốn đường tra cứu (Across firewalls, Path check, From, To) trả lời đúng
cho IP, subnet, protocol và chuỗi nhiều firewall — hoặc nói rõ khi không trả lời
được, thay vì trả lời sai một cách im lặng.

**Bối cảnh:** Kiểm toán ngày 2026-08-11 tìm được **6 lỗi**, tất cả đều chứng minh
được bằng test chạy. Năm trong sáu lỗi khiến công cụ **báo an toàn nhầm hoặc bỏ
sót đường tấn công** — hướng sai nguy hiểm với một công cụ audit.

---

## Kết quả kiểm toán

| # | Lỗi | Hướng sai | Ảnh hưởng |
|---|---|---|---|
| 1 | Subnet bị thu gọn thành **một** địa chỉ | Cả hai | Nghiêm trọng |
| 2 | `protocol=any` báo `pass` khi chỉ một protocol qua được | **Báo an toàn nhầm** | Nghiêm trọng |
| 3 | `explore_to` không bao giờ liệt kê nguồn từ internet | **Bỏ sót** | Nghiêm trọng |
| 4 | `explore_from`/`explore_to` bỏ qua NAT | **Bỏ sót** | Nghiêm trọng |
| 5 | Chuỗi firewall đi theo đích **chưa dịch NAT** | **Bỏ sót** | Nghiêm trọng |
| 6 | Truy vấn IPv6 bị xử lý như không tồn tại, không báo | Im lặng | Trung bình |

### 1. Subnet bị thu gọn thành một địa chỉ

`to_probe_address` nhận `192.168.1.0/24` và trả về `192.168.1.1`. Toàn bộ câu
trả lời sau đó nói về **một host**, nhưng giao diện trình bày như thể nói về cả
subnet.

```
build(): rule 1 block 192.168.1.50 -> any:443
         rule 2 pass  lan          -> any:443

check("192.168.1.50")  -> block     ← đúng
check("192.168.1.9")   -> pass      ← đúng
to_probe_address("192.168.1.0/24") -> "192.168.1.1"   ← cả /24 thành 1 host
```

Người dùng gõ `192.168.1.0/24` và nhận `pass`, không hề biết `.50` bị chặn.

### 2. `protocol=any` nghĩa là "có protocol nào đó", không phải "mọi protocol"

```python
def protocol_matches(rule_protocol, query_protocol):
    if rule_protocol in {"any", ""} or query_protocol == "any":
        return True     # <-- query "any" khớp MỌI rule
```

```
rule: pass tcp lan -> any:443

check(..., "udp") -> block    ← đúng
check(..., "any") -> pass     ← SAI: UDP/443 bị chặn nhưng verdict nói pass
```

Chữ `PASS` cỡ lớn trên giao diện đọc như "luồng này đi được". Thực tế nó chỉ có
nghĩa "tồn tại một protocol nào đó đi được".

### 3. `explore_to` chỉ duyệt subnet của interface

```python
for iface in config.interfaces:      # chỉ có thế
    subnet = resolver.interface_subnet(...)
```

Internet không phải subnet của interface nào, nên tab **To** **không bao giờ**
báo "host này tới được từ internet" — đúng cái nguy hiểm nhất cần biết. Chứng
minh: rule `pass any -> 10.10.20.50:8443` trên WAN, `explore_to` không trả về
nguồn nào ngoài dải nội bộ.

### 4. `explore_from` / `explore_to` bỏ qua NAT

`check` gọi `nat.translate_destination`; hai hàm explore thì không.

```
nat_portforward.xml:
  check("8.8.8.8" -> "203.0.113.2":443)  -> pass    (NAT -> 192.168.1.10:8443)
  explore_from("8.8.8.8") KHÔNG chứa 203.0.113.2
```

Hai đường tính bất đồng. Đây là vi phạm chính bất biến mà `BACKEND_GUIDE.md`
đang khẳng định: "explore_from và check luôn cho cùng kết quả". Test hiện có chỉ
kiểm bất biến đó trên fixture **không có NAT**.

### 5. Chuỗi firewall đi theo đích chưa dịch

```python
decision = check(..., destination, ...)          # check dịch NAT bên trong
route = routing.lookup(table, destination)       # nhưng route dùng đích GỐC
```

Fixture chứng minh: fw-edge có port forward `203.0.113.2:443 -> 10.20.5.10:8443`,
và `10.20.5.10` nằm sau fw-core.

```
path_check("8.8.8.8" -> "203.0.113.2":443)
  thực tế: ['fw-edge']              ← dừng, vì 203.0.113.2 là IP của chính fw-edge
  đúng ra: ['fw-edge', 'fw-core']   ← fw-core CHẶN 8443
  verdict báo: pass                 ← SAI, thực tế bị chặn
```

Mọi dịch vụ publish qua NAT tới host nằm sau firewall thứ hai đều bị đánh giá sai.

### 6. IPv6 bị bỏ qua không báo

`fabric.FAMILY = 4` cố định. `path_check` với nguồn IPv6 trả `unrouted` kèm lý do
sai ("không firewall nào có interface nhận được"), thay vì nói "chưa hỗ trợ IPv6".

---

## Nguyên nhân gốc

Ba nguyên nhân, không phải sáu:

1. **Đầu vào là một địa chỉ, không phải một tập.** `check`, `path_check`,
   `_entry_point` đều nhận `source: str`. Subnet buộc phải bị thu gọn. Lỗi 1.
2. **NAT chỉ sống bên trong `check`.** Không hàm nào khác biết tới nó, và
   `path_check` không nhận lại được đích đã dịch. Lỗi 4 và 5.
3. **"any" bị dùng cho hai nghĩa khác nhau.** Trong rule nó nghĩa "mọi"; trong
   truy vấn nó thành "bất kỳ". Lỗi 2.

Lỗi 3 và 6 là thiếu sót độc lập, sửa riêng.

---

## Quyết định cần bạn chốt

Hai chỗ có nhiều cách hiểu hợp lý và **thay đổi hẳn kết quả**. Mình không tự chọn.

### Q1 — Nhập subnet thì trả lời thế nào?

| | Cách làm | Đánh đổi |
|---|---|---|
| **A** (đề xuất) | Đánh giá cả tập, trả **phân hoạch**: "192.168.1.50 → block, phần còn lại → pass" | Đúng nhất. Nặng nhất: `check` phải chuyển từ điểm sang tập |
| **B** | Chỉ chấp nhận host cho Path check; subnet thì báo lỗi và gợi ý dùng tab From | Rẻ, thành thật, nhưng bỏ mất một câu hỏi hữu ích |
| **C** | Giữ nguyên, nhưng ghi rõ trên kết quả "đã kiểm bằng 192.168.1.1, đại diện cho subnet" | Rẻ nhất. Vẫn có thể dẫn tới kết luận sai nếu người dùng không đọc |

### Q2 — `protocol=any` nghĩa là gì?

| | Cách làm | Đánh đổi |
|---|---|---|
| **A** (đề xuất) | Đánh giá **từng** protocol (tcp, udp, icmp) rồi trả bảng: `tcp → pass, udp → block, icmp → block`. Verdict tổng là "một phần" | Trả lời đúng và đầy đủ. Đổi shape response |
| **B** | `any` nghĩa "mọi protocol": chỉ `pass` khi tất cả đều pass | Đơn giản, an toàn, nhưng giấu mất "tcp thì được" |
| **C** | Bỏ lựa chọn `any`, bắt chọn protocol cụ thể | Rẻ nhất, mất tính tiện |

---

## Kế hoạch sửa

Thứ tự này chọn sao cho **mỗi giai đoạn tự kiểm chứng được** và không giai đoạn
nào phải chờ giai đoạn sau mới đúng.

### Giai đoạn 0 — Đưa 6 probe thành test hồi quy

- [ ] Chép `/tmp/audit_probe.py` thành `tests/engine/test_search_correctness.py`
- [ ] Đánh dấu `@pytest.mark.xfail(strict=True)` cho từng test chưa sửa
- [ ] Chạy: cả 6 phải **xfail**, không test nào xpass
- [ ] Commit — từ đây mọi lỗi đã có lưới an toàn, và bất kỳ ai sửa đúng sẽ thấy
      `strict=True` bắt lỗi ngay khi quên bỏ dấu xfail

### Giai đoạn 1 — NAT vào explore (lỗi 4)

- [ ] `explore_from` áp `nat.translate_destination` giống `check`
- [ ] `explore_to` áp NAT ngược cho đích
- [ ] Bỏ xfail cho probe 4
- [ ] **Bổ sung test bất biến trên fixture CÓ NAT** —
      `test_explore_agrees_with_point_check` hiện chỉ chạy trên fixture không NAT,
      đó là lý do lỗi này lọt qua

### Giai đoạn 2 — Chuỗi firewall đi theo đích đã dịch (lỗi 5)

- [ ] `check` trả về đích và port đã dịch (đã có trong `CheckResult`)
- [ ] `path_check` dùng đích đã dịch cho `routing.lookup` **và** cho chặng sau
- [ ] Ghi cả đích gốc lẫn đích đã dịch vào từng `Hop`
- [ ] Bỏ xfail cho probe 5
- [ ] Thêm fixture `nat_chain_edge.xml` / `nat_chain_core.xml` vào `tests/fixtures/`

### Giai đoạn 3 — Nguồn internet trong `explore_to` (lỗi 3)

- [ ] `explore_to` thêm một nguồn giả "internet" = phần bù của toàn bộ dải nội bộ,
      đi vào qua interface có default route
- [ ] Bỏ xfail cho probe 3
- [ ] Kiểm tra tab **To** trên giao diện có hiện nguồn internet

### Giai đoạn 4 — IPv6 (lỗi 6)

- [ ] `fabric` phát hiện họ địa chỉ từ đầu vào thay vì cố định `FAMILY = 4`
- [ ] Nếu là IPv6: trả `stopped_reason` nói rõ "chưa hỗ trợ IPv6 cho phân tích
      nhiều firewall" thay vì lý do sai
- [ ] Bỏ xfail cho probe 6
- [ ] Ghi giới hạn IPv6 vào README và `BACKEND_GUIDE.md`

### Giai đoạn 5 — Protocol (lỗi 2) — *chờ Q2*

Nội dung phụ thuộc câu trả lời Q2. Nếu chọn A:

- [ ] `check` chạy vòng qua `[tcp, udp, icmp]` khi `protocol="any"`
- [ ] `CheckResult` thêm `per_protocol: dict[str, verdict]`
- [ ] Verdict tổng: `pass` nếu tất cả pass, `block` nếu tất cả block, `partial`
      nếu lẫn lộn — và giao diện phải hiển thị `partial` khác hẳn `pass`
- [ ] Bỏ xfail cho probe 2

### Giai đoạn 6 — Subnet (lỗi 1) — *chờ Q1*

Nội dung phụ thuộc câu trả lời Q1. Nếu chọn A, đây là giai đoạn lớn nhất:

- [ ] `check` nhận `IpSet` thay vì `str` cho nguồn và đích
- [ ] Trả về **danh sách vùng** `(tập nguồn, tập đích, verdict, rule)` thay vì một
      verdict — dùng lại `RectSet` đã có
- [ ] `path_check` truyền tập qua từng chặng
- [ ] Giao diện: Path check và Across firewalls hiển thị bảng vùng khi đầu vào là
      tập, hiển thị verdict đơn khi đầu vào là host
- [ ] Bỏ xfail cho probe 1

### Giai đoạn 7 — Chốt

- [ ] Xoá toàn bộ `xfail`; 6 test phải xanh thật
- [ ] Chạy lại bất biến `explore ≡ check` trên **mọi** fixture, kể cả NAT và
      nhiều firewall
- [ ] Đo lại hiệu năng: giai đoạn 5 và 6 nhân số lần đánh giá lên, kiểm tra
      `access-graph` và `risk` không vượt quá ngưỡng cũ
- [ ] Cập nhật `BACKEND_GUIDE.md`: phần "explore ≡ check" hiện đang khẳng định một
      bất biến mà code chưa giữ

---

## Điều đáng rút kinh nghiệm

Bất biến `explore_from ≡ check` **có** test, và test đó **xanh** suốt — nhưng chỉ
chạy trên hai fixture không có NAT. Một bất biến chỉ mạnh bằng tập dữ liệu nó
được kiểm trên đó. Giai đoạn 7 vì vậy bắt buộc chạy bất biến trên mọi fixture,
không phải trên fixture được chọn lọc.
