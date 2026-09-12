import sys
content = open('litebox_runner_linux_on_windows_userland/examples/sdl_combined_probe.rs').read()
content = content.replace('''struct AudioPacket {
    rate: u32,
    channels: u16,
    bits: u16,
    pcm: Vec<u8>,
}''', '''#[allow(dead_code)]
struct AudioPacket {
    rate: u32,
    channels: u16,
    bits: u16,
    pcm: Vec<u8>,
}''')

content = content.replace('anyhow::ensure!(magic == AUD0_MAGIC, "invalid magic: {:?}", magic);',
                          'anyhow::ensure!(magic == AUD0_MAGIC, "invalid magic: {magic:?}");')

content = content.replace('anyhow::ensure!(pcm_len % 2 == 0, "pcm length must be even: {pcm_len}");',
                          'anyhow::ensure!(pcm_len.is_multiple_of(2), "pcm length must be even: {pcm_len}");')

content = content.replace('for rgb in last.chunks_exact(3) {',
                          'for rgb in last.as_chunks::<3>().0 {')
content = content.replace('for chunk in packet.pcm.chunks_exact(2) {',
                          'for chunk in packet.pcm.as_chunks::<2>().0 {')

open('litebox_runner_linux_on_windows_userland/examples/sdl_combined_probe.rs', 'w').write(content)
