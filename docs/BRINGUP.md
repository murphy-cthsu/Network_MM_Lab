# Pi 5 TPM + IMA Bring-up (Phase 0.3–0.4)

Exact reproduction log for getting the SLB9670 TPM and IMA working on the
Raspberry Pi 5, including every gotcha hit. Target state (Phase 0 gate):
`/dev/tpm0` present, IMA log populated, **PCR 10 non-zero**, tpm2-pytss
quote works.

Hardware/OS as found:

- Raspberry Pi 5 Model B Rev 1.1 (BCM2712), Raspberry Pi OS 64-bit
- Stock kernel `6.12.62+rpt-rpi-2712` (16K pages)
- Infineon OPTIGA SLB9670 on the SPI header

## 1. Enable SPI + TPM overlay

In `/boot/firmware/config.txt`, under `[all]`:

```
dtparam=spi=on
dtoverlay=tpm-slb9670
```

Reboot. Verify:

```
$ ls /dev/tpm0 /dev/tpmrm0
/dev/tpm0  /dev/tpmrm0
$ dmesg | grep -i tpm
tpm_tis_spi spi0.1: 2.0 TPM (device-id 0x1B, rev-id 22)
```

Note: `dmesg` may also show `tpm tpm0: A TPM error (256) occurred attempting
the self test` followed by `starting up the TPM manually` — this is benign
(the kernel polls before the self-test finishes and then starts the TPM
itself).

`tpm2_pcrread sha256:10` works at this point but returns **all zeros** —
expected, because IMA is not measuring anything yet (sections 3–4).

Non-root TPM access: the device nodes are owned by `tss`; add your user to
that group (`sudo usermod -aG tss $USER`, re-login). Our user was already a
member.

## 2. TPM userspace stack

```
sudo apt install tpm2-tools libtss2-dev
```

This gives tpm2-tools 5.7 and tpm2-tss (libtss2) 4.1.3.

### The pytss install gotcha — checked, not applicable here

The course slides warn: if tpm2-tss was ever built from source into
`/usr/local`, `pip install tpm2-pytss` links the wrong tss2 and fails. On
this Pi a source-built **tpm2-tools** exists in `/usr/local/bin` (it shadows
the apt one in `PATH` — harmless, same 5.7 codebase), but there are **no**
`/usr/local/lib/libtss2*`, `/usr/local/include/tss2`, or
`/usr/local/lib/pkgconfig/tss2-*` artifacts; `ldd /usr/local/bin/tpm2_pcrread`
confirms it links the apt libtss2 in `/lib/aarch64-linux-gnu`. So nothing had
to be moved aside. If your Pi *does* have those artifacts, move them away,
run `sudo ldconfig`, and only then install pytss.

### tpm2-pytss in a venv

```
cd ~/Network_MM_Lab
python3 -m venv .venv
.venv/bin/pip install tpm2-pytss        # builds against apt libtss2-dev; needs python3-dev
.venv/bin/python -c "import tpm2_pytss"  # must succeed
```

Installed tpm2-pytss 2.3.0 (cryptography emits two harmless
`CryptographyDeprecationWarning`s on import).

## 3. ESAPI quote sanity check (works before IMA is up)

```
.venv/bin/python dev/quote_sanity.py
```

Creates a *transient* RSA2048 restricted-signing AK via ESAPI (same templates
as `attester/provision.py`), quotes PCR 10 with a fresh 16-byte nonce, checks
the nonce is echoed in `TPMS_ATTEST.extraData`, and verifies the RSASSA/SHA256
signature locally. Output on this Pi:

```
sha256 PCR 10 = 0000000000000000000000000000000000000000000000000000000000000000
transient RSA2048 restricted-signing AK created
quote OK: 129-byte TPMS_ATTEST, nonce echoed in extraData
signature verified locally against the AK public (RSASSA/SHA256)
PASS: ESAPI quote over PCR 10 with an RSA2048 AK works
```

Nothing is persisted, so this is safe to re-run any time (swtpm or Pi).

## 4. THE gotcha (Constraint 4): stock kernel cannot do IMA at all

Two distinct problems, confirmed on `/boot/config-6.12.62+rpt-rpi-2712`:

1. **`# CONFIG_IMA is not set`** — Raspberry Pi OS's stock kernel has no IMA
   support compiled in. Adding `ima_policy=tcb` to the cmdline is a silent
   no-op; `/sys/kernel/security/ima/` never appears. (This is *worse* than
   the documented "No TPM chip found, activating TPM-bypass!" symptom — you
   only get that message once a kernel *with* IMA loads the TPM driver too
   late.)
2. **The whole TPM-over-SPI driver chain is modular**: `CONFIG_TCG_TPM=m`,
   `CONFIG_TCG_TIS_SPI=m`, `CONFIG_SPI_DESIGNWARE=m`, `CONFIG_SPI_DW_MMIO=m`.
   Modules load ~6 s into boot, long after IMA initializes and computes
   `boot_aggregate` — so even with `CONFIG_IMA=y`, a modular TPM driver means
   IMA starts in TPM-bypass mode and PCR 10 stays zero forever.

Fix: build a kernel with IMA enabled **and** the TPM + SPI-controller drivers
built-in. (On the Pi 5 the GPIO-header SPI sits behind the RP1 south bridge:
`tpm_tis_spi` ← `spi-dw-mmio` (DesignWare) ← RP1 ← PCIe. `CONFIG_MFD_RP1=y`
and `CONFIG_PCIE_BRCMSTB=y` are already built-in in the stock config; the
rest must be flipped to `y`.)

## 5. Kernel build (native, on the Pi)

Build deps (only `bison`/`flex` were missing here):

```
sudo apt install -y bc bison flex libssl-dev make gcc git
```

Source: `raspberrypi/linux`, branch `rpi-6.12.y` (same line as the stock
`+rpt` kernel; the branch tip was 6.12.93 when we built — minor drift from
the stock 6.12.62 is fine because the new kernel gets its own modules dir
and its own dtb file):

```
cd ~
git clone --depth=1 --branch rpi-6.12.y https://github.com/raspberrypi/linux.git rpi-linux
cd rpi-linux
make bcm2712_defconfig
./scripts/config \
  --enable CONFIG_TCG_TPM \
  --enable CONFIG_TCG_TIS_CORE \
  --enable CONFIG_TCG_TIS_SPI \
  --enable CONFIG_SPI_DESIGNWARE \
  --enable CONFIG_SPI_DW_MMIO \
  --enable CONFIG_IMA \
  --enable CONFIG_IMA_DEFAULT_HASH_SHA256 \
  --enable CONFIG_IMA_READ_POLICY \
  --set-str CONFIG_LOCALVERSION "-v8-16k-ima"
make olddefconfig
# verify the flips stuck:
grep -E "CONFIG_IMA=|CONFIG_IMA_DEFAULT_HASH_SHA256=|CONFIG_TCG_TPM=|CONFIG_TCG_TIS_SPI=|CONFIG_SPI_DESIGNWARE=|CONFIG_SPI_DW_MMIO=" .config
make -j4 Image.gz modules dtbs   # ~60–90 min on the Pi 5
```

### Gotcha: broken `rpi-6.12.y` branch tip (June 2026)

The tip we cloned (`3f2dce129`, "Merge stable/linux-6.12.y into rpi-6.12.y",
kernel 6.12.93) **does not compile**: the merge left two definitions of
`v3d_cpu_job_free()` in `drivers/gpu/drm/v3d/v3d_submit.c` —

```
drivers/gpu/drm/v3d/v3d_submit.c:184:1: error: redefinition of 'v3d_cpu_job_free'
```

One copy came from the rpi-side clock-management refactor
(`v3d_job_free_common(job, false)`), the other from upstream-stable
memory-leak fixes (frees the timestamp/performance query info and puts the
indirect-CSD BO). We resolved it by hand the way the merge should have:
keep the stable side's body and end it with the rpi side's
`v3d_job_free_common(&job->base, false);` instead of `v3d_job_free(ref);`,
deleting the other duplicate. (Unrelated to our config changes — the V3D GPU
driver builds in any bcm2712 kernel. If a later branch tip compiles cleanly,
none of this applies.)

Build logging note: don't pipe the build through `tail`/`tee` in a script —
you lose the real exit code. Use `make ... > build.log 2>&1; echo $?`.

(`CONFIG_IMA_MEASURE_PCR_IDX` defaults to 10, `ima-ng`/sha256 templates via
`CONFIG_IMA_DEFAULT_HASH_SHA256`. `CONFIG_IMA_READ_POLICY` lets root read
back the active policy from securityfs — handy for Phase 2's model-file
rule.)

Build result on this Pi: exit 0 after the v3d patch; `make kernelrelease` =
`6.12.93-v8-16k-ima+`, `Image.gz` 9.4 MB, 1904 modules.

## 6. Install the kernel (stock kernel kept as fallback)

Nothing stock is overwritten — the new kernel and its device tree go in
under *new names*:

```
cd ~/rpi-linux
sudo make modules_install                                 # → /lib/modules/6.12.93-v8-16k-ima+
sudo cp arch/arm64/boot/Image.gz /boot/firmware/kernel_2712_ima.img
sudo cp arch/arm64/boot/dts/broadcom/bcm2712-rpi-5-b.dtb /boot/firmware/bcm2712-rpi-5-b-ima.dtb
```

In `/boot/firmware/config.txt` under `[all]`, add:

```
kernel=kernel_2712_ima.img
device_tree=bcm2712-rpi-5-b-ima.dtb
```

(Stock overlays — including `tpm-slb9670.dtbo` — are kept; overlay ABI is
stable within the same kernel line.)

Recovery: if the new kernel doesn't boot, mount the SD card's boot partition
on another machine and delete those two lines — the firmware falls back to
the stock `kernel_2712.img` + dtb, which are untouched.

## 7. Enable IMA (`cmdline.txt`)

Append to the single line in `/boot/firmware/cmdline.txt` (it must stay one
line):

```
ima_policy=tcb
```

`tcb` measures all executed binaries/mmapped libs and root-read files into
PCR 10 — enough for Phase 1. (Phase 2 adds a custom rule for the model file.)

## 8. Reboot and verify the Phase 0 gate

```
ls /dev/tpm0                                                  # exists
dmesg | grep -i tpm                                           # NO "TPM-bypass"!
sudo wc -l /sys/kernel/security/ima/ascii_runtime_measurements  # > 0 lines
tpm2_pcrread sha256:10                                        # NON-ZERO
grep boot_aggregate /sys/kernel/security/ima/ascii_runtime_measurements
.venv/bin/python dev/quote_sanity.py                          # PASS again
```

**[TBD — actual outputs to be pasted here]**

## 9. Gotcha #3 (hit at first §8 verify): still TPM-bypass — Pi 5 initcall race

First boot of the custom kernel: `/dev/tpm0` present, IMA log populated
(2351 entries), but **PCR 10 still all zeros** and dmesg still says
`ima: No TPM chip found, activating TPM-bypass!`. The giveaways:

```
[0.264] ima: No TPM chip found, activating TPM-bypass!
[0.518] tpm_tis_spi spi0.1: 2.0 TPM (device-id 0x1B, rev-id 22)
```

and `boot_aggregate` in the IMA log is `sha256:0000…0000` (IMA zeroes it
when no TPM was present at init). Building the drivers in (§4) was
necessary but not sufficient.

Root cause — Pi-5-specific initcall ordering, third layer of the onion:

- The TPM hangs off the GPIO header SPI, which is on **RP1, behind PCIe**
  (`/sys/devices/platform/axi/1000120000.pcie/1f00050000.spi/...`).
- The `brcm-pcie` host probe gets **deferred**; deferred probes are only
  re-run by `deferred_probe_initcall()` — itself a plain `late_initcall`
  in `drivers/base/dd.c`.
- `init_ima` is also a plain `late_initcall`, and `security/` links
  *before* `drivers/` — so IMA initializes (0.264 s) one slot before the
  deferred flush brings up PCIe → RP1 → spi-dw → TPM (0.265–0.518 s).
  IMA checks for a TPM once, finds none, and latches bypass forever.
- The rpi-6.12 kernel already forces the TPM SPI probe synchronous when
  `CONFIG_IMA=y` (`tpm_tis_spi_main.c`), but that can't help: the long
  pole is the deferred *controller chain*, not the TPM probe itself.

Fix — one-line kernel patch in `security/integrity/ima/ima_main.c`:

```diff
-late_initcall(init_ima);	/* Start IMA after the TPM is available */
+late_initcall_sync(init_ima);	/* Start IMA after the TPM is available */
```

`late_initcall_sync` runs after *all* plain late_initcalls, including the
deferred-probe flush; every link in the probe chain is synchronous
(checked: no `PROBE_PREFER_ASYNCHRONOUS` in `pcie-brcmstb.c`, `rp1.c`,
`spi-dw-mmio.c`), so by then the TPM is guaranteed registered.

Rebuild is incremental (one `.o` + relink, minutes not hours), the tree
was already dirty so `kernelrelease` is unchanged → existing modules dir
stays valid; only the image needs recopying:

```
cd ~/rpi-linux
make -j4 Image.gz > build_ima_sync.log 2>&1; echo $?
sudo cp arch/arm64/boot/Image.gz /boot/firmware/kernel_2712_ima.img
sudo reboot
```

Then re-run the §8 checklist.

## Definition-of-done evidence

| Check | Status |
|---|---|
| `ls /dev/tpm0` exists | ✅ (since §1; survived all reboots) |
| `tpm2_pcrread sha256:10` non-zero | ⏳ TBD after §6–8 |
| IMA measurement log non-empty | ⏳ TBD after §6–8 |
| `import tpm2_pytss` + ESAPI RSA2048 quote over PCR 10 | ✅ §2–3 (`dev/quote_sanity.py` PASS) |
