import json, matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
D = json.load(open("bench_data.json")); M = lambda k: D[k]["median"]
BG, FG, MUT = "#0d1117", "#e6edf3", "#8b949e"
C = dict(kem="#58a6ff", dsa="#f78166", aes="#3fb950", other="#6e7681", gold="#d29922")
plt.rcParams.update({"figure.facecolor": BG, "axes.facecolor": BG, "axes.edgecolor": "#30363d", "text.color": FG,
    "axes.labelcolor": FG, "xtick.color": MUT, "ytick.color": MUT, "font.size": 12, "axes.spines.top": False, "axes.spines.right": False})
mach = f"{D['machine']['cpu_model']}, {D['machine']['cpus']} vCPU, Python {D['machine']['python']}, pure-Python kyber-py + dilithium-py"
def foot(fig, extra=""): fig.text(0.01, 0.01, "measured by bench_full.py | " + mach + extra, color=MUT, fontsize=8)

# 1 breakdown
parts = [("ML-KEM keygen (server)", M("mlkem_keygen"), C["kem"]), ("ML-KEM encaps (client)", M("mlkem_encaps"), C["kem"]),
         ("ML-KEM decaps (server)", M("mlkem_decaps"), C["kem"]), ("ML-DSA-65 sign (server)", M("mldsa_sign"), C["dsa"]),
         ("ML-DSA-65 verify (client)", M("mldsa_verify"), C["dsa"])]
tot = M("handshake"); other = max(0, tot - sum(p[1] for p in parts))
fig, ax = plt.subplots(figsize=(11, 4.2)); left = 0
for i, (n, v, c) in enumerate(parts + [("hash, KDF, framing, sockets (remainder)", other, C["other"])]):
    c = c if i < 5 else C["other"]
    ax.barh(0, v, left=left, color=c, edgecolor=BG, linewidth=2, alpha=1 - 0.18 * (i % 3 == 1))
    if v > 3: ax.text(left + v / 2, 0, f"{v:.1f}", ha="center", va="center", color="white", fontweight="bold")
    left += v
ax.set_yticks([]); ax.set_xlabel("milliseconds (sum of component medians; total = measured full-handshake median)")
ax.set_title(f"Where the {tot:.0f} ms goes: ML-DSA signing is {M('mldsa_sign')/tot*100:.0f}% of the handshake", loc="left", fontweight="bold", fontsize=14)
from matplotlib.patches import Patch
ax.legend(handles=[Patch(color=C["kem"], label="ML-KEM-768 (key exchange)"), Patch(color=C["dsa"], label="ML-DSA-65 (server auth)"), Patch(color=C["other"], label="everything else")],
          loc="upper center", bbox_to_anchor=(0.5, -0.25), ncol=3, frameon=False)
foot(fig); fig.tight_layout(rect=(0, 0.03, 1, 1)); fig.savefig("docs/img/handshake-breakdown.png", dpi=160); plt.close()

# 2 primitives
names = ["ML-KEM-768\nkeygen", "ML-KEM-768\nencaps", "ML-KEM-768\ndecaps", "ML-DSA-65\nkeygen", "ML-DSA-65\nsign", "ML-DSA-65\nverify"]
keys = ["mlkem_keygen", "mlkem_encaps", "mlkem_decaps", "mldsa_keygen", "mldsa_sign", "mldsa_verify"]
cols = [C["kem"]] * 3 + [C["dsa"]] * 3
fig, ax = plt.subplots(figsize=(11, 5))
vals = [M(k) for k in keys]; lo = [M(k) - D[k]["min"] for k in keys]; hi = [D[k]["p95"] - M(k) for k in keys]
ax.bar(names, vals, color=cols, yerr=[lo, hi], error_kw=dict(ecolor=MUT, capsize=5))
for i, v in enumerate(vals): ax.text(i, D[keys[i]]["p95"] + 4, f"{v:.1f} ms", ha="center", fontweight="bold")
ax.set_ylabel("ms per operation (median; whiskers = min to p95)")
ax.set_title("Primitive costs: signing is the expensive and the variable one", loc="left", fontweight="bold", fontsize=14)
ax.set_ylim(0, 215); ax.text(0.02, 0.9, "ML-DSA signing uses rejection sampling,\nso its time varies run to run", transform=ax.transAxes, ha="left", va="top", color=MUT, fontsize=10)
foot(fig); fig.tight_layout(rect=(0, 0.03, 1, 1)); fig.savefig("docs/img/primitive-costs.png", dpi=160); plt.close()

# 3 distribution
import numpy as np
h = D["handshake_raw"]
fig, ax = plt.subplots(figsize=(11, 4.6))
ax.hist(h, bins=24, color=C["dsa"], edgecolor=BG)
for k, col, lab in [("median", C["gold"], "median"), ("p95", "#ff7b72", "p95")]:
    ax.axvline(D["handshake"][k], color=col, ls="--"); ax.text(D["handshake"][k] + 3, ax.get_ylim()[1] * .92, f"{lab} {D['handshake'][k]:.0f} ms", color=col, fontweight="bold")
ax.set_xlabel("full authenticated handshake time, ms (client side, localhost)"); ax.set_ylabel("runs (of 100)")
ax.set_title(f"Handshake latency over 100 runs: min {D['handshake']['min']:.0f} ms, max {D['handshake']['max']:.0f} ms", loc="left", fontweight="bold", fontsize=14)
foot(fig); fig.tight_layout(rect=(0, 0.03, 1, 1)); fig.savefig("docs/img/handshake-distribution.png", dpi=160); plt.close()

# 4 bytes
B = D["bytes"]; v1 = B["mlkem_ek"] + B["mlkem_ct"]
fig, ax = plt.subplots(figsize=(11, 4))
segs1 = [("ML-KEM key + ciphertext", v1, C["kem"])]
segs2 = [("ML-KEM key + ciphertext + nonces + magic", B["total_v02"] - B["signature"] - B["mldsa_pk"], C["kem"]), ("ML-DSA public key", B["mldsa_pk"], "#ffa657"), ("ML-DSA signature", B["signature"], C["dsa"])]
for y, segs, lab in [(1, segs1, "v0.1 (unauthenticated)"), (0, segs2, "v0.2 (authenticated)")]:
    l = 0
    for n, v, c in segs:
        ax.barh(y, v, left=l, color=c, edgecolor=BG, linewidth=2); ax.text(l + v / 2, y, f"{v:,}", ha="center", va="center", fontweight="bold", color="white"); l += v
    ax.text(l + 80, y, f"{l:,} B", va="center", fontweight="bold")
ax.set_yticks([0, 1]); ax.set_yticklabels(["v0.2 (authenticated)", "v0.1 (unauthenticated)"]); ax.set_xlim(0, 9000)
ax.set_xlabel("handshake bytes on the wire (excluding 4-byte frame headers)")
ax.legend(handles=[Patch(color=C["kem"], label="ML-KEM-768 + nonces"), Patch(color="#ffa657", label="ML-DSA-65 public key"), Patch(color=C["dsa"], label="ML-DSA-65 signature")], loc="upper right", frameon=False)
ax.set_title(f"Authentication costs {B['total_v02']-v1:,} extra bytes ({B['total_v02']/v1:.1f}x the v0.1 handshake)", loc="left", fontweight="bold", fontsize=14)
foot(fig, " | sizes are protocol constants"); fig.tight_layout(rect=(0, 0.03, 1, 1)); fig.savefig("docs/img/handshake-bytes.png", dpi=160); plt.close()

# 5 protocol diagram
fig, ax = plt.subplots(figsize=(11, 6.8)); ax.set_xlim(0, 11); ax.set_ylim(0, 7); ax.axis("off")
for x, n in [(2, "Client"), (9, "Server")]:
    ax.add_patch(FancyBboxPatch((x - .9, 5.6), 1.8, .55, boxstyle="round,pad=0.05", fc="#161b22", ec="#30363d")); ax.text(x, 5.875, n, ha="center", va="center", fontweight="bold", fontsize=13)
    ax.plot([x, x], [0.3, 5.55], color="#30363d", lw=2, ls=":")
def arrow(y, x1, x2, text, sub, col):
    ax.add_patch(FancyArrowPatch((x1, y), (x2, y), arrowstyle="-|>", mutation_scale=18, color=col, lw=2.2))
    ax.text(5.5, y + .12, text, ha="center", fontweight="bold", color=col, fontsize=11); ax.text(5.5, y - .28, sub, ha="center", color=MUT, fontsize=9)
arrow(4.7, 9, 2, "1  ServerHello", f"ML-DSA-65 public key ({B['mldsa_pk']:,} B) | ML-KEM-768 key ({B['mlkem_ek']:,} B) | nonce (32 B)", C["kem"])
ax.text(2, 4.0, "check key against pin / TOFU\nabort here if it is not the trusted key", ha="center", va="top", color=C["gold"], fontsize=9)
arrow(3.1, 2, 9, "2  ClientKey", f"\"PQS2\" | client nonce (32 B) | ML-KEM ciphertext ({B['mlkem_ct']:,} B)", C["kem"])
ax.text(9, 2.4, "decapsulate shared secret\nsign the full transcript", ha="center", va="top", color=MUT, fontsize=9)
arrow(1.5, 9, 2, "3  Signature", f"ML-DSA-65 signature over both messages ({B['signature']:,} B)", C["dsa"])
ax.text(2, 0.85, "verify signature; drop the connection if invalid\nHKDF-SHA256 -> two AES-256-GCM keys", ha="center", va="top", color=C["aes"], fontsize=9)
ax.text(9, .85, "same HKDF -> same keys", ha="center", va="top", color=C["aes"], fontsize=9)
ax.text(.1, 6.95, "pqsecure v0.2 handshake: three messages, one signature", fontweight="bold", fontsize=14, va="top")
fig.tight_layout(); fig.savefig("docs/img/protocol.png", dpi=160); plt.close()
print("ok", other)
