import { describe, expect, it } from "vitest";

import { csvField, toCsv } from "./csv";

describe("csvField", () => {
  it("leaves a plain value alone", () => {
    expect(csvField("192.168.1.0/24")).toBe("192.168.1.0/24");
  });

  it("quotes a value containing a comma", () => {
    expect(csvField("10.0.0.0/8, 172.16.0.0/12")).toBe('"10.0.0.0/8, 172.16.0.0/12"');
  });

  it("doubles inner quotes", () => {
    expect(csvField('the "DMZ" zone')).toBe('"the ""DMZ"" zone"');
  });

  it("quotes a value containing a newline", () => {
    expect(csvField("line one\nline two")).toBe('"line one\nline two"');
  });

  it("neutralises a value that would run as a formula", () => {
    // A pfSense description is somebody else's text. Excel would execute this.
    expect(csvField("=1+1")).toBe("'=1+1");
    expect(csvField("@SUM(A1)")).toBe("'@SUM(A1)");
    expect(csvField("+1")).toBe("'+1");
    expect(csvField("-1")).toBe("'-1");
  });

  it("quotes a neutralised value that also contains a comma", () => {
    expect(csvField("=cmd|'/c calc'!A1, x")).toBe(`"'=cmd|'/c calc'!A1, x"`);
  });
});

describe("toCsv", () => {
  it("writes a header row and CRLF line endings", () => {
    expect(toCsv(["a", "b"], [["1", "2"]])).toBe("a,b\r\n1,2");
  });

  it("writes only the header when there are no rows", () => {
    expect(toCsv(["a", "b"], [])).toBe("a,b");
  });
});
