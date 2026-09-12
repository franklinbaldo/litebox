# LiteBox desktop experiments

The Breakout demo runs Linux game logic with Windows video, input and audio.
The next step is reusable SDL support. SDL2 probes now validate surface frames,
synthetic keyboard press/release and focus reset, and callback audio through
host-owned pipes. See [reproducible SDL checks](../../examples/sdl_probe/README.md).

The SDL fixtures remain separate: physical keyboard routing, combined video and
audio, resize, persistence and existing-game compatibility are not yet validated.
Builds use external Zig/musl; no compiler executes inside LiteBox.

- [Compatibility scope](general-compatibility.md)
- [Game corpus and acceptance plan](game-corpus.md)
- [SDL backend design proposal](sdl-backend-plan.md)
- [Windows installation proposal](windows-install-plan.md)
- [Proposed package schema](game-package.schema.json)

The planning documents describe future work, not completed features. The probes
use LBDF v1 framing and fixture-specific FRAM, KEY0, FOC0 and AUD0/ACK0 payloads;
the older LBG1 design is not their implemented wire format. New host and transport
code is Rust. Small SDL driver patches preserve upstream C authorship and license.

Generated binaries, downloaded SDL sources and machine-specific logs stay under
ignored target directories. Only source, build recipes and documentation belong
in this change.
