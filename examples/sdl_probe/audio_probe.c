// Copyright (c) franklinbaldo.
// Licensed under the MIT license.

#include <SDL.h>
#include <stdint.h>

#define TARGET_CALLBACKS 8
#define MAX_APP_TIME_MS 5000

static SDL_atomic_t g_callback_count;
static int g_phase = 0;

static void SDLCALL audio_callback(void *userdata, Uint8 *stream, int len)
{
    int16_t *samples = (int16_t *)stream;
    int count = len / (int)sizeof(int16_t);
    int i;
    (void)userdata;

    for (i = 0; i < count; ++i) {
        /* Square wave ~441 Hz at 22050 Hz (half period 25 samples: +4000 then -4000) */
        samples[i] = (g_phase < 25) ? (int16_t)4000 : (int16_t)(-4000);
        g_phase = (g_phase + 1) % 50;
    }

    SDL_AtomicAdd(&g_callback_count, 1);
}

int main(int argc, char *argv[])
{
    SDL_AudioSpec desired;
    SDL_AudioSpec obtained;
    SDL_AudioDeviceID dev;
    Uint32 start_ticks;
    int callbacks_done;

    (void)argc;
    (void)argv;

    SDL_AtomicSet(&g_callback_count, 0);

    if (SDL_Init(SDL_INIT_AUDIO) < 0) {
        return 1;
    }

    SDL_zero(desired);
    desired.freq = 22050;
    desired.format = AUDIO_S16LSB;
    desired.channels = 1;
    desired.samples = 512;
    desired.callback = audio_callback;
    desired.userdata = NULL;

    SDL_zero(obtained);
    dev = SDL_OpenAudioDevice(NULL, 0, &desired, &obtained, 0);
    if (dev == 0) {
        SDL_Quit();
        return 2;
    }

    /* Verify obtained specification */
    if (obtained.freq != 22050 || obtained.format != AUDIO_S16LSB ||
        obtained.channels != 1 || obtained.samples != 512) {
        SDL_CloseAudioDevice(dev);
        SDL_Quit();
        return 3;
    }

    /* Start playback in real SDL audio thread */
    SDL_PauseAudioDevice(dev, 0);

    /* Wait for ~8 callbacks using SDL_Delay and atomic counter (or max 5s timeout) */
    start_ticks = SDL_GetTicks();
    while ((callbacks_done = SDL_AtomicGet(&g_callback_count)) < TARGET_CALLBACKS) {
        if ((SDL_GetTicks() - start_ticks) >= MAX_APP_TIME_MS) {
            break;
        }
        SDL_Delay(10);
    }

    /* Pause and close device */
    SDL_PauseAudioDevice(dev, 1);
    SDL_CloseAudioDevice(dev);

    SDL_Quit();

    return (callbacks_done >= TARGET_CALLBACKS) ? 0 : 4;
}
