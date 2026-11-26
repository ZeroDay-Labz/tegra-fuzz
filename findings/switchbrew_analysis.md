# Switchbrew Analysis Notes (2026-11-19)

## IPATCH Mechanism (from Fuses page)
- Patches burned into fuses, initialize IPATCH hardware at boot
- Each entry patches a single Thumb-2 instruction halfword at a bootROM address
- CAM (Content Addressable Memory): address = 0x100000 + ((entry >> 16) * 2)
- Can patch to: `svc #imm` (redirect to handler), `movs r0/r1, #imm`, `bx lr`, or raw halfword
- SVC handlers stored in IRAM at 0x40004C30 (T210)
- SVC dispatch base addresses: 0x001007B0, 0x001007F8
- Erista has 12 patches (0-11), linked list in fuse space
- Hamming-16 ECC protects each record

## Erista IPATCH Patches (from switchbrew Fuses)
- Patch 0: Clock enables (various CLK registers)
- Patch 1: PMC_SCRATCH190 OR 0x01
- Patch 2: USB UTMIP config
- **Patch 3: 0x0010769A — `movs r1, #0` — limits wLength to 255 (CVE-2018-6242 fix, 0xE0 units)**
  - On earlier units (0xA0, 0xC0): handles PRC_PENDING waits instead
- Patch 4: Warmboot straps
- Patch 5: USB UTMIP config
- Patch 6: Debug auth (FUSE_ODM_INFO, IRAM 0x400028E4)
- Patch 7: Warmboot size check (oversized → MAIN_RST deadlock)
- Patch 8: Warmboot entry (0x40010238 → 0x40004C28)
- Patches 9-10: Secure Provisioning AES key (index 0x3A)
- Patch 11: SE_TZRAM_SECURITY = 0x01

## FUSE_OPT_FT_REV Values (Erista)
- 0xA0 (rev 5.0): Original, unpatched
- 0xC0 (rev 6.0): First patched batch
- 0xE0 (rev 7.0): Second patched batch (wLength cap in Patch 3)

## IRAM Memory Map (from BCT/Package1 pages)
- 0x40000000: BCT (Boot Configuration Table, ~0x2800 bytes)
- 0x400028E4: Debug auth IPATCH target
- 0x40004C28: Warmboot entry (Patch 8 target)
- 0x40004C30: IPATCH SVC handler base (T210)
- 0x40005000: (from IRAM leak)
- 0x40007000: NX boot stub stack
- 0x40008000: Initial stack pointer
- 0x40009000: DMA/RCM data buffer
- 0x40010000: Bootloader load address
- 0x40010020: Entry point (1.0.0-3.0.2)
- 0x40010040: Entry point (4.0.0+)
- 0x40013FE0: PK11 blob address

## BCT BootLoader0 Info
- LoadAddress: 0x40010000
- EntryPoint: 0x40010020 (old) / 0x40010040 (new)
- StartBlock: 0x40 (normal) / 0x100 (safe mode)
- Length: variable
- CryptoHash: empty
- RsaPssSig at BCT+0x235C

## Key Fuse Addresses
- 0x7000F800: Fuse controller base
- 0x7000F900: PRODUCTION_MODE
- 0x7000F910: SKU_INFO (must be 0x83)
- 0x7000F928: OPT_FT_REV (patch generation)
- 0x7000F934: SOC_SPEEDO_1_CALIB (bootrom patch version)
- 0x7000F960: ENCRYPTION_RATE
- 0x7000F964-0x7000F980: PUBLIC_KEY (RSA key hash, 8 words)
- 0x7000F99C: FIRST_BOOTROM_PATCH_SIZE
- 0x7000F9A0: SECURITY_MODE
- 0x7000F9A4-0x7000F9B4: PRIVATE_KEY (SBK + device key, 5 words)
- 0x7000F9C0: RESERVED_SW (boot config: bit 7 = RCM USB controller)
- 0x7000F9C8-0x7000F9E4: RESERVED_ODM (anti-downgrade fuses)

## Open Questions
1. Where is the DMA overflow fix? Patch 3 only caps wLength (EP0), not bulk DMA
2. Is the DMA cap in the first-patch batch (0xC0) IPATCH but not documented?
3. Does our unit have FUSE_OPT_FT_REV 0xE0 (second patch)?
4. Are there unpatched vulnerabilities beyond the 12 IPATCH entries?
5. Can SVC handler code at 0x40004C30 be corrupted before it executes?

## IPATCH Decoder
- https://gist.github.com/hexkyz/98c28e292597d8fc7bef7a2200e792d7
- Takes 0x400-byte fuse image, outputs decoded patches
- CAM format: address = ROM_BASE + ((entry >> 16) * 2), data = halfword
