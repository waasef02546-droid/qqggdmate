from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple


def _hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _stream(label: str, length: int) -> bytes:
    out = b""
    counter = 0
    seed = label.encode("utf-8")
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _canonical_json(data: dict) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Agent:
    agent_id: str
    public_key: str
    private_key: str

    @staticmethod
    def create(agent_id: str) -> "Agent":
        private_key = hashlib.sha256(f"pre-saga:sk:{agent_id}".encode()).hexdigest()
        public_key = hashlib.sha256(f"pre-saga:pk:{agent_id}".encode()).hexdigest()
        return Agent(agent_id=agent_id, public_key=public_key, private_key=private_key)


@dataclass
class ContactToken:
    issuer: str
    owner_agent: str
    requester_agent: str
    issued_at: float
    expires_at: float
    max_uses: int
    uses: int = 0
    signature: str = ""

    def payload(self) -> dict:
        return {
            "issuer": self.issuer,
            "owner_agent": self.owner_agent,
            "requester_agent": self.requester_agent,
            "issued_at": round(self.issued_at, 3),
            "expires_at": round(self.expires_at, 3),
            "max_uses": self.max_uses,
        }

    def digest(self) -> str:
        payload = self.payload()
        payload["signature"] = self.signature
        return hashlib.sha256(_canonical_json(payload)).hexdigest()


@dataclass(frozen=True)
class DataSharingRule:
    requester_agent: str
    data_class: str
    purpose: str
    ttl_seconds: int
    max_uses: int


@dataclass
class DataSharingPolicy:
    owner_agent: str
    rules: List[DataSharingRule]

    def find_rule(self, requester_agent: str, data_class: str, purpose: str) -> Optional[DataSharingRule]:
        for rule in self.rules:
            if (
                rule.requester_agent == requester_agent
                and rule.data_class == data_class
                and rule.purpose == purpose
            ):
                return rule
        return None


@dataclass
class EncryptedRecord:
    record_id: str
    owner_agent: str
    data_class: str
    ciphertext: bytes
    encrypted_dek: bytes
    metadata: Dict[str, str] = field(default_factory=dict)


class PolicyError(ValueError):
    pass


class ToyPRE:
    """A tiny PRE behavior model.

    This demonstrates re-encryption semantics only:
    Enc(pk, dek) = dek XOR H(pk), rk_a_b = H(pk_a) XOR H(pk_b).
    A real system must replace this with a vetted PRE/KEM library.
    """

    @staticmethod
    def encrypt_key(public_key: str, dek: bytes) -> bytes:
        return _xor(dek, _stream(public_key, len(dek)))

    @staticmethod
    def decrypt_key(public_key: str, encrypted_dek: bytes) -> bytes:
        return _xor(encrypted_dek, _stream(public_key, len(encrypted_dek)))

    @staticmethod
    def rekey(from_public_key: str, to_public_key: str, context: str) -> bytes:
        # The context binds the transform to a token/policy decision in the audit layer.
        del context
        left = _stream(from_public_key, 32)
        right = _stream(to_public_key, 32)
        return _xor(left, right)

    @staticmethod
    def transform(encrypted_dek: bytes, re_encryption_key: bytes) -> bytes:
        return _xor(encrypted_dek, re_encryption_key[: len(encrypted_dek)])


class ProviderPREProxy:
    def __init__(self, provider_secret: bytes):
        self.provider_secret = provider_secret
        self.contact_policies: Dict[str, Set[str]] = {}
        self.data_policies: Dict[str, DataSharingPolicy] = {}
        self.agents: Dict[str, Agent] = {}
        self.audit_log: List[str] = []

    def register_agent(self, agent: Agent, allowed_contacts: Iterable[str]) -> None:
        self.agents[agent.agent_id] = agent
        self.contact_policies[agent.agent_id] = set(allowed_contacts)

    def set_data_policy(self, policy: DataSharingPolicy) -> None:
        self.data_policies[policy.owner_agent] = policy

    def issue_contact_token(
        self,
        owner_agent: str,
        requester_agent: str,
        ttl_seconds: int = 300,
        max_uses: int = 5,
    ) -> ContactToken:
        if requester_agent not in self.contact_policies.get(owner_agent, set()):
            raise PolicyError("requester is not allowed by Agent Contact Policy")
        now = time.time()
        token = ContactToken(
            issuer="provider",
            owner_agent=owner_agent,
            requester_agent=requester_agent,
            issued_at=now,
            expires_at=now + ttl_seconds,
            max_uses=max_uses,
        )
        token.signature = hmac.new(self.provider_secret, _canonical_json(token.payload()), hashlib.sha256).hexdigest()
        return token

    def re_encrypt_data_key(
        self,
        token: ContactToken,
        record: EncryptedRecord,
        requester_agent: str,
        purpose: str,
    ) -> bytes:
        started = time.perf_counter()
        self._verify_token(token, record.owner_agent, requester_agent)
        policy = self.data_policies.get(record.owner_agent)
        if policy is None:
            raise PolicyError("owner has no Data Sharing Policy")
        rule = policy.find_rule(requester_agent, record.data_class, purpose)
        if rule is None:
            raise PolicyError("request denied by Data Sharing Policy")

        owner = self._agent(record.owner_agent)
        requester = self._agent(requester_agent)
        context = f"{token.digest()}:{record.record_id}:{record.data_class}:{purpose}"
        rk = ToyPRE.rekey(owner.public_key, requester.public_key, context)
        converted = ToyPRE.transform(record.encrypted_dek, rk)
        token.uses += 1
        elapsed_ms = (time.perf_counter() - started) * 1000
        self.audit_log.append(
            "allow_re_encrypt "
            f"owner={record.owner_agent} requester={requester_agent} data_class={record.data_class} "
            f"purpose={purpose} token={token.digest()} elapsed_ms={elapsed_ms:.3f}"
        )
        return converted

    def _verify_token(self, token: ContactToken, owner_agent: str, requester_agent: str) -> None:
        expected = hmac.new(self.provider_secret, _canonical_json(token.payload()), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, token.signature):
            raise PolicyError("invalid contact token signature")
        if token.owner_agent != owner_agent:
            raise PolicyError("token owner mismatch")
        if token.requester_agent != requester_agent:
            raise PolicyError("token requester mismatch")
        if token.expires_at < time.time():
            raise PolicyError("contact token expired")
        if token.uses >= token.max_uses:
            raise PolicyError("contact token quota exceeded")

    def _agent(self, agent_id: str) -> Agent:
        if agent_id not in self.agents:
            raise PolicyError(f"unknown agent: {agent_id}")
        return self.agents[agent_id]


def encrypt_record(owner: Agent, record_id: str, data_class: str, plaintext: str) -> Tuple[EncryptedRecord, bytes]:
    dek = _hash(f"dek:{owner.agent_id}:{record_id}:{data_class}".encode())
    data = plaintext.encode("utf-8")
    ciphertext = _xor(data, _stream(dek.hex(), len(data)))
    encrypted_dek = ToyPRE.encrypt_key(owner.public_key, dek)
    return (
        EncryptedRecord(
            record_id=record_id,
            owner_agent=owner.agent_id,
            data_class=data_class,
            ciphertext=ciphertext,
            encrypted_dek=encrypted_dek,
            metadata={"cipher": "toy-envelope-xor", "pre": "toy-transform"},
        ),
        dek,
    )


def decrypt_record(requester: Agent, record: EncryptedRecord, converted_encrypted_dek: bytes) -> str:
    dek = ToyPRE.decrypt_key(requester.public_key, converted_encrypted_dek)
    plaintext = _xor(record.ciphertext, _stream(dek.hex(), len(record.ciphertext)))
    return plaintext.decode("utf-8")
