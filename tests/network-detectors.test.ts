import { describe, expect, it } from "@jest/globals";
import { countNetwork, networkMode, scanNetwork } from "../src/network-detectors.js";
import { detectSensitive, redactSensitive } from "../src/data-detectors.js";
import { TOPOLOGY_KINDS } from "../src/network-detectors.js";

const kinds = (text: string) => scanNetwork(text).map(h => h.kind);

describe("network classification", () => {
  const cases: Array<[string, string[]]> = [
    ["ssh 10.0.0.5", ["INTERNAL_IP"]], ["host 172.16.4.9 and 172.31.255.1", ["INTERNAL_IP", "INTERNAL_IP"]], ["172.32.0.1", ["PUBLIC_IP"]],
    ["192.168.1.1", ["INTERNAL_IP"]], ["100.64.0.1", ["INTERNAL_IP"]], ["169.254.169.254", ["INTERNAL_IP"]], ["dns 8.8.8.8", ["PUBLIC_IP"]],
    ["vpc 10.0.0.0/16", ["NETWORK_RANGE"]], ["allow 52.1.2.0/24", ["NETWORK_RANGE"]], ["range 10.0.0.1-10.0.0.50", ["NETWORK_RANGE"]], ["pool 192.168.1.10-50", ["NETWORK_RANGE"]],
    ["fd12:3456:789a::1", ["INTERNAL_IP"]], ["fe80::1ff:fe23:4567:890a", ["INTERNAL_IP"]], ["2606:4700:4700::1111", ["PUBLIC_IP"]], ["fd00::/8", ["NETWORK_RANGE"]],
    ["::ffff:10.1.2.3", ["INTERNAL_IP"]], ["::ffff:8.8.4.4", ["PUBLIC_IP"]],
    ["db.prod.internal", ["INTERNAL_HOST"]], ["api.corp", ["INTERNAL_HOST"]], ["svc.default.svc.cluster.local", ["INTERNAL_HOST"]], ["ip-10-0-1-5.ec2.internal", ["INTERNAL_HOST"]], ["printer.lan", ["INTERNAL_HOST"]],
  ];
  it.each(cases)("classifies %s", (text, expected) => { expect(kinds(text)).toEqual(expected); });

  const ignored = [
    "127.0.0.1", "localhost", "0.0.0.0", "255.255.255.255", "224.0.0.1", "::1", "::", "2001:db8::1", "203.0.113.0/24", "198.51.100.7", "192.0.2.1",
    "v1.2.3.4", "version 1.2.3", "12:34:56", "aa:bb:cc:dd:ee:ff", "2026-11-12 12:44:53", "settings.local.json", ".env.local", "config.local", "foo.local.bak",
    "std::vector", "Foo::bar", "a@host.internal.com", "999.1.1.1", "10.0.0.256", "0.12 0.08 1.5 2.25", "3.14159", "192.168.1", "1.2.3.4.5",
  ];
  it.each(ignored)("does not report %s", (text) => { expect(kinds(text)).toEqual([]); });

  it("counts by kind and never returns an address", () => {
    const counts = countNetwork("a 10.0.0.1 b 10.0.0.2 c 8.8.8.8 d db.corp e 10.0.0.0/8");
    expect(counts).toEqual({ INTERNAL_IP: 2, PUBLIC_IP: 1, INTERNAL_HOST: 1, NETWORK_RANGE: 1 });
    expect(JSON.stringify(counts)).not.toMatch(/\d+\.\d+\.\d+/);
  });

  it("resolves mode from policy, then env, defaulting to report", () => {
    expect(networkMode(undefined, undefined)).toBe("report");
    expect(networkMode("block", "off")).toBe("block");
    expect(networkMode(undefined, "redact")).toBe("redact");
    expect(networkMode("nonsense", undefined)).toBe("report");
  });
});

describe("topology in the shared detectors", () => {
  it("redacts internal addresses, ranges and hosts but leaves a public IP alone", () => {
    expect(redactSensitive("ssh 10.0.0.5 via db.prod.internal on 10.0.0.0/16, dns 8.8.8.8").text)
      .toBe("ssh [INTERNAL_IP_REDACTED] via [INTERNAL_HOST_REDACTED] on [NETWORK_RANGE_REDACTED], dns 8.8.8.8");
  });
  it("lets a caller skip topology (model-facing text under report mode) while the default keeps it out of logs", () => {
    expect(detectSensitive("ssh 10.0.0.5").map(f => f.kind)).toEqual(["INTERNAL_IP"]);
    expect(detectSensitive("ssh 10.0.0.5", [], { skipKinds: TOPOLOGY_KINDS })).toEqual([]);
  });
});
