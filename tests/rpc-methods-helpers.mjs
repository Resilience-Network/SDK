import { readFileSync } from "node:fs";
import { ChainRpcClient, AUTHORIZATION_CAPABILITY, hexToBytes } from "../dist/index.js";
import { FakeClock, url } from "./rpc-helpers.mjs";

export const fixtureFile = JSON.parse(
  readFileSync(new URL("./fixtures/rpc-contracts.json", import.meta.url), "utf8"),
);
export const fixtures = fixtureFile.fixtures;
export const findFixture = (scenario, method) =>
  fixtures.find((f) => f.scenario === scenario && f.method === method);
export const expected = {
  chainId: 1337n,
  genesisHash: hexToBytes(`0x${"00".repeat(31)}aa`),
  authorizationCapability: AUTHORIZATION_CAPABILITY,
};

export function methodHarness(
  fixture,
  { mutate = () => {}, options = {}, fetch: customFetch } = {},
) {
  const clock = new FakeClock(),
    calls = [];
  const fetch = async (endpoint, init) => {
    const requests = JSON.parse(init.body);
    calls.push({ endpoint, init, requests });
    if (customFetch) return customFetch(requests, calls.length, init);
    const responses = requests.map((request, index) => {
      let response;
      if (request.method === "rsc_getAuthorizationFinalityStatus")
        response = structuredClone(fixture.identity);
      else {
        const match =
          request.method === fixture.method
            ? fixture
            : (findFixture(fixture.scenario, request.method) ??
              findFixture("direct", request.method));
        if (!match) throw new Error(`Missing fixture for ${request.method}`);
        response = structuredClone(match.response);
      }
      response.id = request.id;
      mutate(response, request, calls.length, index);
      return response;
    });
    return new Response(JSON.stringify(responses.reverse()));
  };
  return {
    client: new ChainRpcClient({ url, expected, fetch, clock, ...options }),
    calls,
    clock,
  };
}

export function invokeFixture(client, fixture, options) {
  const p =
    fixture.method === "rsc_feeHistory"
      ? []
      : fixture.params.map((value) => hexToBytes(value));
  switch (fixture.method) {
    case "rsc_getAuthorizationFinalityStatus":
      return client.getAuthorizationFinalityStatus(options);
    case "rsc_getRootAuthority":
      return client.getRootAuthority(p[0], options);
    case "rsc_getSessionGrant":
      return client.getSessionGrant(p[0], p[1], options);
    case "rsc_getSessionNonce":
      return client.getSessionNonce(p[0], p[1], options);
    case "rsc_getSessionUsage":
      return client.getSessionUsage(p[0], p[1], options);
    case "rsc_decodePolicy":
      return client.decodePolicy(p[0], options);
    case "rsc_previewPolicy":
      return client.previewPolicy(p[0], options);
    case "rsc_gasPrice":
    case "rsc_maxPriorityFeePerGas":
      return client.getFeeSuggestions(options);
    case "rsc_feeHistory":
      return client.getFeeHistory(
        {
          blockCount: Number(BigInt(fixture.params[0])),
          newestBlock:
            fixture.params[1] === "latest" ? "latest" : BigInt(fixture.params[1]),
          rewardPercentiles: fixture.params[2],
        },
        options,
      );
    case "rsc_estimateAuthorizationGas":
      return client.estimateAuthorizationGas(p[0], options);
    case "rsc_simulateAuthorizedTransaction":
      return client.simulateAuthorizedTransaction(p[0], options);
    default:
      throw new Error(`Uncovered fixture ${fixture.method}`);
  }
}
