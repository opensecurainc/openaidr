import { test, expect } from "@playwright/test";
import { cvssBaseScore, highestCvssScore } from "../src/lib/cvss";

const v3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:L";

test("CVSS base scores match reference vectors and exclude optional adjustments", () => {
  // FIRST reference examples: https://www.first.org/cvss/v4.0/examples
  // and the v2, v3.0 and v3.1 specification equations.
  for (const [type, vector, version, expected] of [
    ["CVSS_V2", "AV:N/AC:L/Au:N/C:C/I:C/A:C", "2.0", 10],
    ["CVSS_V2", "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C/E:U/RL:OF/RC:UC/CDP:N/TD:N", "2.0", 10],
    ["CVSS_V3", v3.replace("3.1", "3.0"), "3.0", 9.8],
    ["CVSS_V3", v3, "3.1", 9.8],
    ["CVSS_V3", `${v3}/E:U/RL:O/RC:U/MC:N/MI:N/MA:N`, "3.1", 9.8],
    ["CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "3.1", 6.1],
    ["CVSS_V3", "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N", "3.1", 9.8],
    ["CVSS_V4", v4, "4.0", 8.7],
    ["CVSS_V4", `${v4}/E:U/MVA:H/MSA:N`, "4.0", 8.7],
    ["CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N", "4.0", 5.1],
    ["CVSS_V4", "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "4.0", 9.4],
    ["CVSS_V4", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "4.0", 0],
    ["CVSS_V3", v3.replace("C:H/I:H/A:H", "C:N/I:N/A:N"), "3.1", 0],
    ["CVSS_V2", "AV:N/AC:L/Au:N/C:N/I:N/A:N", "2.0", 0],
  ] as const) {
    expect(cvssBaseScore({ type, score: vector }), vector).toEqual({ score: expected, version, vector });
  }
});

test("CVSS rejects malformed evidence and selects the highest valid score deterministically", () => {
  for (const [type, score] of [
    ["CVSS_V3", ""], ["CVSS_V3", "9.8"], ["CVSS_V3", "Critical"],
    ["CVSS_V3", "CVSS:3.1/AV:N"], ["CVSS_V3", v3.replace("/A:H", "")],
    ["CVSS_V3", `${v3}/AV:N`], ["CVSS_V3", `${v3}/EXTRA:H`],
    ["CVSS_V3", `${v3}/E:INVALID`], ["CVSS_V3", `${v3}/`],
    ["CVSS_V3", v3.replace("AV:N", "AV:X")], ["CVSS_V3", v3.replace("AV:N", "AV:Network")],
    ["CVSS_V3", v3.replace("AV:N", "AV:N:extra")], ["CVSS_V3", `${v3}\n`],
    ["CVSS_V3", v4], ["CVSS_V4", v3], ["CVSS_V2", v3],
    ["CVSS_V3", v3.replace("3.1", "3.2")], ["CVSS_V5", v4.replace("4.0", "5.0")],
    ["CVSS_V4", v4.replace("/SA:L", "")], ["CVSS_V4", `${v4}/MSA:INVALID`],
    ["CVSS_V2", "AV:N/AC:L/Au:N/C:C/I:C"], ["CVSS_V2", "AV:N/AC:L/Au:N/C:C/I:C/A:X"],
  ]) expect(cvssBaseScore({ type, score }), score).toBeNull();
  const lower = { type: "CVSS_V4", score: v4 };
  const winner = { type: "CVSS_V3", score: v3 };
  const earlier = { ...winner, score: v3.replace("3.1", "3.0") };
  const invalid = { type: "CVSS_V3", score: "10.0" };
  for (const vectors of [[lower, earlier, winner, invalid], [invalid, winner, earlier, lower]]) {
    expect(highestCvssScore(vectors)).toEqual({ score: 9.8, version: "3.1", vector: v3 });
  }
  expect(highestCvssScore([invalid])).toBeNull();
  expect(highestCvssScore([])).toBeNull();
});
