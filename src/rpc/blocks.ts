import { checkedUint, isZero } from "../core/bytes.js";
import type { AuthorizationFinalityStatus } from "./contracts.js";
import {
  array,
  quantity,
  record,
  requireResult,
  sameBytes,
  wireBytes,
} from "./validate.js";

/** Checks a pinned RPC projection, not native header hashing or a certificate. */
export function finalizedTransactionBlock(
  value: unknown,
  number: bigint,
  blockHash: Uint8Array,
  transactionIndex: bigint,
  transactionHash: Uint8Array,
  identity: AuthorizationFinalityStatus,
  checkObservedHead = true,
): boolean {
  if (value === null) return false;
  const r = record(value, [
    "number",
    "hash",
    "parentHash",
    "nonce",
    "sha3Uncles",
    "logsBloom",
    "transactionsRoot",
    "stateRoot",
    "receiptsRoot",
    "miner",
    "difficulty",
    "totalDifficulty",
    "extraData",
    "size",
    "gasLimit",
    "gasUsed",
    "baseFeePerGas",
    "timestamp",
    "transactions",
    "uncles",
    "slot",
    "round",
    "epoch",
  ]);
  requireResult(quantity(r.number) === number);
  if (checkObservedHead) requireResult(number <= identity.state.height);
  sameBytes(wireBytes(r.hash, 32, 32), blockHash);
  requireResult(!isZero(blockHash));
  for (const field of [
    "parentHash",
    "sha3Uncles",
    "transactionsRoot",
    "stateRoot",
    "receiptsRoot",
  ])
    wireBytes(r[field], 32, 32);
  if (checkObservedHead && number === identity.state.height) {
    sameBytes(blockHash, identity.state.blockHash);
    sameBytes(wireBytes(r.stateRoot, 32, 32), identity.state.stateRoot);
  }
  const nonce = wireBytes(r.nonce, 8, 8),
    bloom = wireBytes(r.logsBloom, 256, 256);
  requireResult(
    isZero(nonce) && isZero(bloom) && isZero(wireBytes(r.sha3Uncles, 32, 32)),
  );
  wireBytes(r.miner, 20, 20);
  wireBytes(r.extraData, 256);
  requireResult(
    quantity(r.difficulty) === 1n &&
      quantity(r.totalDifficulty) === number &&
      quantity(r.size) === 4096n,
  );
  requireResult(quantity(r.gasUsed) <= quantity(r.gasLimit));
  quantity(r.baseFeePerGas, 256);
  quantity(r.timestamp);
  array(r.uncles, 0, 0);
  for (const field of ["slot", "round", "epoch"]) {
    const text = r[field];
    requireResult(
      typeof text === "string" && text.length <= 20 && /^(0|[1-9][0-9]*)$/.test(text),
    );
    checkedUint(BigInt(text), field === "round" ? 32 : 64);
  }
  const transactions = array(r.transactions, 0, 65536).map((v) => wireBytes(v, 32, 32));
  requireResult(transactionIndex < BigInt(transactions.length));
  sameBytes(transactions[Number(transactionIndex)]!, transactionHash);
  return true;
}
