test("blocks sensitive paths", () => {
  expect(isAllowed("/etc/passwd")).toBe(false);
});
