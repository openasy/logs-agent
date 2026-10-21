import { describe, expect, it } from "vitest";
import { CA_FILE, hostSetup, sshdConfig } from "./setup.ts";

const CA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFmXq7hWQvK1eF4s3n0q6X8b9mZ2nqJ8V7cJq3s1kR2x OpenAsy logs-agent CA";

describe("host setup", () => {
  it("adds this agent's CA to the file infra-agent uses too, and lets the account read the journal", () => {
    const s = hostSetup(CA, { containers: false });
    expect(s).toContain(`grep -qxF '${CA}' ${CA_FILE} || echo '${CA}' >> ${CA_FILE}`);
    expect(s).toContain("usermod -aG systemd-journal openasy");
    expect(s).not.toContain("sudoers");
    expect(s).not.toContain("docker");
  });

  it("joins the docker group only when containers are read", () => {
    expect(hostSetup(CA, { containers: true })).toContain("usermod -aG docker openasy");
  });

  it("trusts the CA for the openasy principal only", () => {
    expect(sshdConfig()).toContain(`TrustedUserCAKeys ${CA_FILE}`);
    expect(sshdConfig()).toMatch(/AuthorizedPrincipalsFile/);
  });
});
