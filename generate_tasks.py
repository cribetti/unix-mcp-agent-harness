import argparse
import hashlib
import json
import os
import random
import subprocess
from typing import Any


KOTLIN_BANKS = [
    "Ledger", "Vault", "Settlement", "Treasury", "Escrow", "Clearing",
    "Custody", "Remittance", "Wire", "Account", "Card", "Token",
]
KOTLIN_SUFFIXES = [
    "Guard", "Store", "Pool", "Queue", "Cache", "Registry", "Gate", "Router",
]
CPP_MODULES = [
    "jni_bridge", "native_vault", "session_ring", "crypto_buf", "bio_cache",
    "telemetry_mux", "audit_ring", "keystore_shim",
]
C_MODULES = [
    "ringbuf", "workq", "slab", "hashmap", "rwmap", "barrier", "timerq", "sempool",
]


def _make_id(prefix: str, idx: int, spec: str) -> str:
    digest = hashlib.sha1(spec.encode("utf-8")).hexdigest()[:6]
    return f"{prefix}_{idx:03d}_{digest}"


def _gen_kotlin_concurrency(rng: random.Random, idx: int) -> dict[str, Any]:
    variant = idx % 4
    bank = rng.choice(KOTLIN_BANKS)
    threads = rng.choice([4, 6, 8])
    iters = rng.choice([100, 150, 200, 250])
    cap = rng.choice([3, 4, 5, 6])

    if variant == 0:
        cls = f"{bank}Accumulator"
        expected = threads * iters
        spec = (
            f"Fix the race condition in `{cls}.kt` by guarding shared state with `ReentrantLock` "
            f"(using `try {{ ... }} finally {{ lock.unlock() }}`). Do NOT modify the test invariants in `Main.kt`, "
            f"and do NOT import `kotlin.test.*`. Ensure `compile_and_test` prints 'ALL TESTS PASSED'."
        )
        broken_cls = f"""class {cls} {{
    private var balance: Long = 0L
    private val entries = mutableListOf<String>()

    fun record(tag: String, amount: Long) {{
        val next = balance + amount
        Thread.yield()
        balance = next
        entries.add(tag)
    }}

    fun totalBalance(): Long = balance
    fun entryCount(): Int = entries.size
}}
"""
        main_kt = f"""import java.util.concurrent.CountDownLatch

fun main() {{
    val acc = {cls}()
    val start = CountDownLatch(1)
    val workers = (0 until {threads}).map {{ tid ->
        Thread {{
            start.await()
            for (i in 0 until {iters}) {{
                acc.record("t$tid-$i", 1L)
            }}
        }}
    }}
    workers.forEach {{ it.start() }}
    start.countDown()
    workers.forEach {{ it.join() }}
    assert(acc.totalBalance() == {expected}L) {{ "Expected {expected}, got ${{acc.totalBalance()}}" }}
    assert(acc.entryCount() == {expected}) {{ "Expected {expected} entries, got ${{acc.entryCount()}}" }}
    println("ALL TESTS PASSED")
}}
"""
        return {
            "id": _make_id("kt_conc", idx, spec),
            "category": "kotlin_concurrency",
            "spec": spec,
            "workspace_files": {
                f"{cls}.kt": broken_cls,
                "Main.kt": main_kt,
            },
        }

    if variant == 1:
        cls = f"{bank}BoundedPool"
        total_ops = threads * 25
        spec = (
            f"Fix `{cls}.kt` so `acquire()` and `release()` are thread-safe and properly block when empty/full "
            f"using `ReentrantLock` and `Condition` (`try {{ ... }} finally {{ lock.unlock() }}`), avoiding "
            f"lost wakeups (`signalAll()`). Do NOT import `kotlin.test.*`. Verify `Main.kt` prints 'ALL TESTS PASSED'."
        )
        broken_cls = f"""import java.util.ArrayDeque

class {cls}(private val capacity: Int) {{
    private val items = ArrayDeque<Int>((0 until capacity).toList())

    fun acquire(): Int {{
        if (items.isEmpty()) {{
            throw IllegalStateException("Pool exhausted without blocking")
        }}
        return items.removeFirst()
    }}

    fun release(item: Int) {{
        items.addLast(item)
    }}
}}
"""
        main_kt = f"""import java.util.concurrent.atomic.AtomicInteger

fun main() {{
    val pool = {cls}({cap})
    val completed = AtomicInteger(0)
    val active = AtomicInteger(0)
    val maxSeen = AtomicInteger(0)
    val workers = (0 until {threads}).map {{
        Thread {{
            for (i in 0 until 25) {{
                val slot = pool.acquire()
                val cur = active.incrementAndGet()
                maxSeen.accumulateAndGet(cur, Math::max)
                Thread.sleep(1)
                active.decrementAndGet()
                pool.release(slot)
                completed.incrementAndGet()
            }}
        }}
    }}
    workers.forEach {{ it.start() }}
    workers.forEach {{ it.join() }}
    assert(completed.get() == {total_ops}) {{ "Completed=${{completed.get()}}" }}
    assert(maxSeen.get() <= {cap}) {{ "Exceeded capacity: ${{maxSeen.get()}}" }}
    println("ALL TESTS PASSED")
}}
"""
        return {
            "id": _make_id("kt_conc", idx, spec),
            "category": "kotlin_concurrency",
            "spec": spec,
            "workspace_files": {
                f"{cls}.kt": broken_cls,
                "Main.kt": main_kt,
            },
        }

    if variant == 2:
        cls = f"{bank}Dispatcher"
        spec = (
            f"Create `Main.kt` implementing a thread-safe single-lane `{cls}` coroutine-style task serializer "
            f"using `ReentrantLock` (`try {{ ... }} finally {{ lock.unlock() }}`) and a `Condition` worker queue "
            f"so `submit(task)` executes tasks strictly FIFO without concurrent overlap. In `Main.kt`, use `Thread {{ ... }}` "
            f"and `assert(condition)` (do NOT import `kotlin.test.*` or `kotlinx.coroutines`) to verify {threads} threads "
            f"x {iters} tasks complete in-order with zero overlap, printing 'ALL TESTS PASSED'."
        )
        return {
            "id": _make_id("kt_conc", idx, spec),
            "category": "kotlin_concurrency",
            "spec": spec,
        }

    cls = f"{bank}CircuitBreaker"
    spec = (
        f"Create `Main.kt` implementing a thread-safe `{cls}(failureThreshold = {cap}, cooldownMs = 30L)` "
        f"using `ReentrantLock` (`try {{ ... }} finally {{ lock.unlock() }}`). In `Main.kt`, use `Thread {{ ... }}` "
        f"and `assert(condition)` (do NOT import `kotlin.test.*`) to verify CLOSED -> OPEN after {cap} failures, "
        f"rejection while OPEN, transition to HALF_OPEN after cooldown, and concurrent calls across {threads} threads, "
        f"printing 'ALL TESTS PASSED'."
    )
    return {
        "id": _make_id("kt_conc", idx, spec),
        "category": "kotlin_concurrency",
        "spec": spec,
    }


def _gen_ndk_cpp_cmake(rng: random.Random, idx: int) -> dict[str, Any]:
    variant = idx % 4
    mod = rng.choice(CPP_MODULES)
    threads = rng.choice([4, 6, 8])
    iters = rng.choice([200, 400, 500])
    cap = rng.choice([16, 32, 64])

    if variant == 0:
        spec = (
            f"Fix the `CMakeLists.txt` build failure and C++17 `std::mutex` bug in `{mod}.hpp`/`{mod}.cpp` so "
            f"`cmake` builds and `ctest` passes with zero warnings/deadlocks."
        )
        cmake = f"""cmake_minimum_required(VERSION 3.16)
project({mod}_proj LANGUAGES CXX)
enable_testing()
# BUG: missing C++17 standard and Threads link, and test_{mod}.cpp omitted
add_executable(test_{mod} {mod}.cpp)
add_test(NAME {mod}_suite COMMAND test_{mod})
"""
        hpp = f"""#pragma once
#include <mutex>
#include <vector>
#include <cstdint>

class NativeSessionBuffer {{
public:
    explicit NativeSessionBuffer(std::size_t cap) : cap_(cap) {{}}
    bool push_token(int64_t val);
    std::size_t size() const;
    int64_t sum() const;
private:
    std::size_t cap_;
    mutable std::mutex mu_;
    std::vector<int64_t> data_;
}};
"""
        cpp = f"""#include "{mod}.hpp"
#include <numeric>

bool NativeSessionBuffer::push_token(int64_t val) {{
    std::lock_guard<std::mutex> lock(mu_);
    if (size() >= cap_) {{  // BUG: self-deadlock calling size() while holding non-recursive mu_
        return false;
    }}
    data_.push_back(val);
    return true;
}}

std::size_t NativeSessionBuffer::size() const {{
    std::lock_guard<std::mutex> lock(mu_);
    return data_.size();
}}

int64_t NativeSessionBuffer::sum() const {{
    std::lock_guard<std::mutex> lock(mu_);
    return std::accumulate(data_.begin(), data_.end(), int64_t{{0}});
}}
"""
        test_cpp = f"""#include "{mod}.hpp"
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>

int main() {{
    NativeSessionBuffer buf({cap});
    std::vector<std::thread> pool;
    for (int t = 0; t < {threads}; ++t) {{
        pool.emplace_back([&buf]() {{
            for (int i = 0; i < 4; ++i) {{
                buf.push_token(1);
            }}
        }});
    }}
    for (auto& th : pool) th.join();
    assert(buf.size() == static_cast<std::size_t>({threads * 4}));
    assert(buf.sum() == {threads * 4});
    std::cout << "ALL TESTS PASSED\\n";
    return 0;
}}
"""
        return {
            "id": _make_id("ndk_cpp", idx, spec),
            "category": "ndk_cpp_cmake",
            "spec": spec,
            "workspace_files": {
                "CMakeLists.txt": cmake,
                f"{mod}.hpp": hpp,
                f"{mod}.cpp": cpp,
                f"test_{mod}.cpp": test_cpp,
            },
        }

    if variant == 1:
        spec = (
            f"Fix the JNI-style UTF-8 C++17 buffer truncation/off-by-one and `std::mutex` race in `{mod}.hpp`/`{mod}.cpp` "
            f"and ensure `CMakeLists.txt` builds and passes `ctest` across {threads} threads."
        )
        cmake = f"""cmake_minimum_required(VERSION 3.16)
project({mod}_jni LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
enable_testing()
find_package(Threads REQUIRED)
add_executable(test_{mod} {mod}.cpp test_{mod}.cpp)
target_link_libraries(test_{mod} PRIVATE Threads::Threads)
add_test(NAME {mod}_jni_test COMMAND test_{mod})
"""
        hpp = """#pragma once
#include <mutex>
#include <string>

class JniStringSlot {
public:
    void set(const char* src);
    std::string get() const;

private:
    mutable std::mutex mu_;
    char buf_[32] = {0};
};
"""
        cpp = f"""#include "{mod}.hpp"
#include <cstring>

void JniStringSlot::set(const char* src) {{
    // BUG: missing mutex lock and off-by-one null terminator copy
    if (!src) return;
    std::size_t n = std::strlen(src);
    if (n > sizeof(buf_)) n = sizeof(buf_);
    std::memcpy(buf_, src, n);
}}

std::string JniStringSlot::get() const {{
    return std::string(buf_);
}}
"""
        test_cpp = f"""#include "{mod}.hpp"
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>

int main() {{
    JniStringSlot slot;
    std::string long_input(64, 'A');
    slot.set(long_input.c_str());
    assert(slot.get().size() == 31);

    std::vector<std::thread> workers;
    for (int t = 0; t < {threads}; ++t) {{
        workers.emplace_back([&slot, t]() {{
            for (int i = 0; i < {iters}; ++i) {{
                std::string s = "token_" + std::to_string(t);
                slot.set(s.c_str());
                assert(!slot.get().empty());
            }}
        }});
    }}
    for (auto& w : workers) w.join();
    std::cout << "ALL TESTS PASSED\\n";
    return 0;
}}
"""
        return {
            "id": _make_id("ndk_cpp", idx, spec),
            "category": "ndk_cpp_cmake",
            "spec": spec,
            "workspace_files": {
                "CMakeLists.txt": cmake,
                f"{mod}.hpp": hpp,
                f"{mod}.cpp": cpp,
                f"test_{mod}.cpp": test_cpp,
            },
        }

    if variant == 2:
        spec = (
            f"Fix the lock-ordering deadlock and `CMakeLists.txt` C++17 standard in `{mod}.hpp`/`{mod}.cpp` and "
            f"`CMakeLists.txt` using `std::scoped_lock` across dual account transfers so `ctest` passes."
        )
        cmake = f"""cmake_minimum_required(VERSION 3.16)
project({mod}_ledger LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
enable_testing()
find_package(Threads REQUIRED)
add_executable(test_{mod} {mod}.cpp test_{mod}.cpp)
target_link_libraries(test_{mod} PRIVATE Threads::Threads)
add_test(NAME {mod}_deadlock_test COMMAND test_{mod})
"""
        hpp = """#pragma once
#include <cstdint>
#include <mutex>

struct NativeAccount {
    std::mutex mu;
    int64_t balance{1000};
};

bool transfer(NativeAccount& from, NativeAccount& to, int64_t amount);
"""
        cpp = f"""#include "{mod}.hpp"

bool transfer(NativeAccount& from, NativeAccount& to, int64_t amount) {{
    if (&from == &to || amount <= 0) return false;
    // BUG: locks in caller order -> AB/BA deadlock under concurrent opposite transfers
    std::lock_guard<std::mutex> g1(from.mu);
    std::lock_guard<std::mutex> g2(to.mu);
    if (from.balance < amount) return false;
    from.balance -= amount;
    to.balance += amount;
    return true;
}}
"""
        test_cpp = f"""#include "{mod}.hpp"
#include <cassert>
#include <iostream>
#include <thread>

int main() {{
    NativeAccount a, b;
    std::thread t1([&]() {{
        for (int i = 0; i < {iters}; ++i) transfer(a, b, 1);
    }});
    std::thread t2([&]() {{
        for (int i = 0; i < {iters}; ++i) transfer(b, a, 1);
    }});
    t1.join();
    t2.join();
    assert(a.balance + b.balance == 2000);
    std::cout << "ALL TESTS PASSED\\n";
    return 0;
}}
"""
        return {
            "id": _make_id("ndk_cpp", idx, spec),
            "category": "ndk_cpp_cmake",
            "spec": spec,
            "workspace_files": {
                "CMakeLists.txt": cmake,
                f"{mod}.hpp": hpp,
                f"{mod}.cpp": cpp,
                f"test_{mod}.cpp": test_cpp,
            },
        }

    spec = (
        f"Create `CMakeLists.txt`, `{mod}.hpp`, `{mod}.cpp`, and `test_{mod}.cpp` implementing a thread-safe "
        f"C++17 `NativeRingCache` (capacity {cap}) guarded by `std::mutex` and `std::lock_guard`, with `ctest` "
        f"verifying {threads} concurrent threads and printing 'ALL TESTS PASSED'."
    )
    return {
        "id": _make_id("ndk_cpp", idx, spec),
        "category": "ndk_cpp_cmake",
        "spec": spec,
    }


def _gen_owasp_masvs(rng: random.Random, idx: int) -> dict[str, Any]:
    variant = idx % 4
    bank = rng.choice(KOTLIN_BANKS)
    suffix = rng.choice(KOTLIN_SUFFIXES)
    cls = f"{bank}{suffix}"

    if variant == 0:
        secret_sample = f"sk_live_{rng.randint(100000, 999999)}_{bank.lower()}"
        spec = (
            f"Remediate the OWASP MASVS-STORAGE hardcoded secret vulnerability in `{cls}.kt`: remove the "
            f"hardcoded signing secret, require an injected/environment secret provider (throwing `IllegalStateException` "
            f"if blank), use HMAC-SHA256 with constant-time `MessageDigest.isEqual`, and make `verifyToken` pass "
            f"all assertions in `Main.kt` (do NOT import `kotlin.test.*`)."
        )
        broken_kt = f"""class {cls}(private val keyProvider: () -> ByteArray = {{ ByteArray(0) }}) {{
    companion object {{
        private const val HARDCODED_SECRET = "{secret_sample}"
    }}

    fun signToken(payload: String): ByteArray {{
        return (HARDCODED_SECRET + ":" + payload).toByteArray(Charsets.UTF_8)
    }}

    fun verifyToken(payload: String, sig: ByteArray): Boolean {{
        return signToken(payload).contentEquals(sig)
    }}
}}
"""
        main_kt = f"""import java.io.File

fun main() {{
    val src = File("{cls}.kt").readText()
    assert(!src.contains("{secret_sample}")) {{ "Hardcoded secret still present!" }}
    assert(!src.contains("HARDCODED_SECRET")) {{ "Hardcoded constant still present!" }}

    var failedEmpty = false
    try {{
        {cls} {{ ByteArray(0) }}.signToken("acct=42")
    }} catch (_: IllegalStateException) {{
        failedEmpty = true
    }}
    assert(failedEmpty) {{ "Blank key must throw IllegalStateException" }}

    val key = "bank-rotated-ephemeral-key-32bytes".toByteArray()
    val store = {cls} {{ key }}
    val sig = store.signToken("acct=42")
    assert(store.verifyToken("acct=42", sig))
    assert(!store.verifyToken("acct=99", sig))
    println("ALL TESTS PASSED")
}}
"""
        return {
            "id": _make_id("masvs", idx, spec),
            "category": "owasp_masvs",
            "spec": spec,
            "workspace_files": {
                f"{cls}.kt": broken_kt,
                "Main.kt": main_kt,
            },
        }

    if variant == 1:
        spec = (
            f"Remediate the OWASP MASVS-STORAGE / path-traversal vulnerability in `{cls}.kt`: enforce strict "
            f"`canonicalPath` sandbox jailing inside `rootDir` (rejecting absolute paths, `../` traversal, and "
            f"symlinks escaping `rootDir` with `SecurityException`), and ensure all assertions in `Main.kt` pass."
        )
        broken_kt = f"""import java.io.File

class {cls}(private val rootDir: File) {{
    init {{ rootDir.mkdirs() }}

    fun readEntry(relPath: String): String {{
        val target = File(rootDir, relPath)
        return target.readText(Charsets.UTF_8)
    }}

    fun writeEntry(relPath: String, content: String) {{
        val target = File(rootDir, relPath)
        target.parentFile?.mkdirs()
        target.writeText(content, Charsets.UTF_8)
    }}
}}
"""
        main_kt = f"""import java.io.File
import java.nio.file.Files

fun main() {{
    val tmp = Files.createTempDirectory("masvs_jail_").toFile()
    val outside = Files.createTempFile("masvs_secret_", ".txt").toFile()
    outside.writeText("TOP_SECRET_BANK_KEY")
    val sandbox = File(tmp, "sandbox")
    val store = {cls}(sandbox)
    store.writeEntry("ok.txt", "safe-payload")
    assert(store.readEntry("ok.txt") == "safe-payload")

    var blockedTraversal = false
    try {{
        store.readEntry("../" + outside.name)
    }} catch (_: SecurityException) {{
        blockedTraversal = true
    }}
    assert(blockedTraversal) {{ "Path traversal was not blocked!" }}

    var blockedAbs = false
    try {{
        store.readEntry(outside.absolutePath)
    }} catch (_: SecurityException) {{
        blockedAbs = true
    }}
    assert(blockedAbs) {{ "Absolute path escape was not blocked!" }}

    val sym = File(sandbox, "escape_link.txt").toPath()
    Files.createSymbolicLink(sym, outside.toPath())
    var blockedSymlink = false
    try {{
        store.readEntry("escape_link.txt")
    }} catch (_: SecurityException) {{
        blockedSymlink = true
    }}
    assert(blockedSymlink) {{ "Symlink escape was not blocked!" }}
    println("ALL TESTS PASSED")
}}
"""
        return {
            "id": _make_id("masvs", idx, spec),
            "category": "owasp_masvs",
            "spec": spec,
            "workspace_files": {
                f"{cls}.kt": broken_kt,
                "Main.kt": main_kt,
            },
        }

    if variant == 2:
        spec = (
            f"Remediate the OWASP MASVS-CRYPTO vulnerability in `{cls}.kt`: replace `AES/ECB/PKCS5Padding` and "
            f"static zero IV with `AES/GCM/NoPadding` using a fresh 12-byte `SecureRandom` IV per encryption and "
            f"128-bit authentication tag, storing `iv || ciphertext` so `Main.kt` assertions pass."
        )
        broken_kt = f"""import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class {cls}(private val rawKey: ByteArray) {{
    fun encrypt(plaintext: ByteArray): ByteArray {{
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(rawKey, "AES"))
        return cipher.doFinal(plaintext)
    }}

    fun decrypt(ciphertext: ByteArray): ByteArray {{
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(rawKey, "AES"))
        return cipher.doFinal(ciphertext)
    }}
}}
"""
        main_kt = f"""import java.io.File
import java.security.SecureRandom

fun main() {{
    val src = File("{cls}.kt").readText()
    assert(!src.contains("AES/ECB")) {{ "Insecure AES/ECB still used!" }}
    assert(src.contains("AES/GCM/NoPadding")) {{ "Must use AES/GCM/NoPadding" }}

    val key = ByteArray(16).also {{ SecureRandom().nextBytes(it) }}
    val vault = {cls}(key)
    val msg = "routing=021000021;acct=998877".toByteArray()
    val c1 = vault.encrypt(msg)
    val c2 = vault.encrypt(msg)
    assert(!c1.contentEquals(c2)) {{ "Ciphertext must use fresh random IV!" }}
    assert(vault.decrypt(c1).contentEquals(msg))

    val tampered = c1.copyOf()
    tampered[tampered.lastIndex] = (tampered.last().toInt() xor 0xFF).toByte()
    var authFailed = false
    try {{
        vault.decrypt(tampered)
    }} catch (_: Exception) {{
        authFailed = true
    }}
    assert(authFailed) {{ "GCM tag verification must reject tampered ciphertext!" }}
    println("ALL TESTS PASSED")
}}
"""
        return {
            "id": _make_id("masvs", idx, spec),
            "category": "owasp_masvs",
            "spec": spec,
            "workspace_files": {
                f"{cls}.kt": broken_kt,
                "Main.kt": main_kt,
            },
        }

    spec = (
        f"Remediate the OWASP MASVS-STORAGE insecure SharedPreferences/PII logging flaw in `{cls}.kt`: "
        f"encrypt stored preference values (never persist plaintext PAN/PIN/tokens to disk) and redact "
        f"sensitive tokens in `auditSummary()`, passing all assertions in `Main.kt`."
    )
    broken_kt = f"""import java.io.File

class {cls}(private val prefsFile: File, private val masterKey: ByteArray) {{
    private val entries = linkedMapOf<String, String>()

    fun putSecret(key: String, secretValue: String) {{
        entries[key] = secretValue
        prefsFile.writeText(entries.entries.joinToString("\\n") {{ "${{it.key}}=${{it.value}}" }})
    }}

    fun getSecret(key: String): String? = entries[key]

    fun auditSummary(): String {{
        return entries.entries.joinToString(", ") {{ "${{it.key}}=${{it.value}}" }}
    }}
}}
"""
    main_kt = f"""import java.io.File
import java.nio.file.Files
import java.security.SecureRandom

fun main() {{
    val f = Files.createTempFile("secure_prefs_", ".dat").toFile()
    val key = ByteArray(16).also {{ SecureRandom().nextBytes(it) }}
    val store = {cls}(f, key)
    val pan = "4111222233334444"
    store.putSecret("card_pan", pan)
    assert(store.getSecret("card_pan") == pan)
    val disk = f.readText()
    assert(!disk.contains(pan)) {{ "Plaintext PAN persisted on disk!" }}
    val summary = store.auditSummary()
    assert(!summary.contains(pan)) {{ "Plaintext PAN leaked in auditSummary!" }}
    println("ALL TESTS PASSED")
}}
"""
    return {
        "id": _make_id("masvs", idx, spec),
        "category": "owasp_masvs",
        "spec": spec,
        "workspace_files": {
            f"{cls}.kt": broken_kt,
            "Main.kt": main_kt,
        },
    }


def _gen_c_systems(rng: random.Random, idx: int) -> dict[str, Any]:
    mod = rng.choice(C_MODULES)
    threads = rng.choice([4, 6, 8])
    items_per_thread = rng.choice([50, 100, 150])
    cap = rng.choice([8, 16, 32])
    variant = idx % 2

    if variant == 0:
        spec = (
            f"Create `{mod}.c` implementing a thread-safe bounded ring buffer of capacity {cap} using "
            f"`pthread_mutex_t` and `pthread_cond_t`, plus a `main()` spawning {threads} producer and {threads} "
            f"consumer threads ({items_per_thread} items per producer) verifying exact sum with `assert`, "
            f"printing 'ALL TESTS PASSED'."
        )
    else:
        total = threads * items_per_thread
        spec = (
            f"Create `{mod}.c` implementing a thread-safe concurrent integer hash table or bucket counter "
            f"with per-bucket `pthread_mutex_t` locks, plus a `main()` spawning {threads} threads inserting "
            f"{items_per_thread} keys each and verifying total count == {total} with `assert`, "
            f"printing 'ALL TESTS PASSED'."
        )
    return {
        "id": _make_id("c_sys", idx, spec),
        "category": "c_systems",
        "spec": spec,
    }


def generate_tasks(count: int = 120, seed: int = 42) -> list[dict[str, Any]]:
    """Deterministically generate Android/Kotlin/NDK/C and OWASP MASVS tasks."""
    rng = random.Random(seed)
    generators = [
        _gen_kotlin_concurrency,
        _gen_ndk_cpp_cmake,
        _gen_owasp_masvs,
        _gen_c_systems,
    ]
    tasks: list[dict[str, Any]] = []
    seen_specs: set[str] = set()
    attempt = 0
    while len(tasks) < count:
        gen_idx = attempt % len(generators)
        cat_idx = attempt // len(generators)
        gen = generators[gen_idx]
        task = gen(rng, cat_idx)
        attempt += 1
        if task["spec"] in seen_specs:
            continue
        seen_specs.add(task["spec"])
        tasks.append(task)
    return tasks


def materialize_tasks(tasks: list[dict[str, Any]], out_dir: str) -> int:
    """Materialize workspace-backed tasks onto disk for direct `orchestrator.py --workspace` usage."""
    os.makedirs(out_dir, exist_ok=True)
    written = 0
    for task in tasks:
        ws_files = task.get("workspace_files")
        if not ws_files:
            continue
        task_dir = os.path.join(out_dir, task["id"])
        os.makedirs(task_dir, exist_ok=True)
        for rel_path, content in ws_files.items():
            full = os.path.join(task_dir, rel_path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as f:
                f.write(content)
        with open(os.path.join(task_dir, "TASK.md"), "w", encoding="utf-8") as f:
            f.write(task["spec"] + "\n")
        subprocess.run(
            "git init -q && git config user.email 'agent@local' && git config user.name 'Agent' "
            "&& git add -A && git commit --allow-empty -m 'baseline' -q",
            shell=True,
            cwd=task_dir,
            check=True,
        )
        written += 1
    return written


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description="Generate deterministic Android/Kotlin/NDK/OWASP RLVR tasks")
    parser.add_argument("--count", type=int, default=120, help="Total tasks to generate (default: 120)")
    parser.add_argument("--seed", type=int, default=42, help="PRNG seed for deterministic generation")
    parser.add_argument(
        "--out",
        default=os.path.join(here, "generated_tasks.json"),
        help="Output JSON tasks file (compatible with eval.py --tasks-file and harvest_rlvr.py)",
    )
    parser.add_argument("--eval-out", default=None, help="Optional held-out eval split JSON output path")
    parser.add_argument("--eval-count", type=int, default=20, help="Number of tasks to hold out when --eval-out is set")
    parser.add_argument(
        "--materialize-dir",
        default=None,
        help="Optional directory to write workspace-backed tasks for `orchestrator.py --workspace`",
    )
    args = parser.parse_args()

    tasks = generate_tasks(count=args.count, seed=args.seed)

    if args.eval_out:
        split = min(max(1, args.eval_count), len(tasks) - 1) if len(tasks) > 1 else 0
        eval_tasks = tasks[-split:] if split else []
        train_tasks = tasks[:-split] if split else tasks
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(train_tasks, f, indent=2)
        with open(args.eval_out, "w", encoding="utf-8") as f:
            json.dump(eval_tasks, f, indent=2)
        print(f"[Tasks] Wrote {len(train_tasks)} train tasks -> {args.out}, {len(eval_tasks)} eval tasks -> {args.eval_out}")
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(tasks, f, indent=2)
        print(f"[Tasks] Wrote {len(tasks)} deterministic tasks -> {args.out}")

    by_cat: dict[str, int] = {}
    for t in tasks:
        by_cat[t["category"]] = by_cat.get(t["category"], 0) + 1
    print(f"[Tasks] Category breakdown: {json.dumps(by_cat)}")

    if args.materialize_dir:
        n_mat = materialize_tasks(tasks, args.materialize_dir)
        print(f"[Tasks] Materialized {n_mat} git workspaces in {args.materialize_dir}")


if __name__ == "__main__":
    main()
