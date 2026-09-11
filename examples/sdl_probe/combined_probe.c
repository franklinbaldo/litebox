#include "SDL.h"
#include <stdint.h>
#include <stdio.h>

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
        samples[i] = (g_phase < 25) ? (int16_t)4000 : (int16_t)(-4000);
        g_phase = (g_phase + 1) % 50;
    }

    SDL_AtomicAdd(&g_callback_count, 1);
}

static int present(SDL_Window *w, unsigned char r, unsigned char g, unsigned char b, int rect_x) {
    SDL_Surface *s = SDL_GetWindowSurface(w);
    SDL_Rect center = {rect_x,45,40,30};
    if (!s || SDL_FillRect(s, NULL, SDL_MapRGB(s->format,r,g,b)) < 0 ||
        SDL_FillRect(s,&center,SDL_MapRGB(s->format,255,255,255)) < 0) return -1;
    return SDL_UpdateWindowSurface(w);
}

int main(int argc, char *argv[])
{
    SDL_Window *window;
    SDL_AudioSpec desired;
    SDL_AudioSpec obtained;
    SDL_AudioDeviceID dev;
    int stage=0;
    Uint32 start;
    int rect_x = 60;

    (void)argc;
    (void)argv;

    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) < 0) {
        return 1;
    }

    window = SDL_CreateWindow("LiteBox Combined Probe",
                              SDL_WINDOWPOS_UNDEFINED,
                              SDL_WINDOWPOS_UNDEFINED,
                              160, 120, 0);
    if (!window) {
        return 2;
    }

    SDL_AtomicSet(&g_callback_count, 0);

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
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 3;
    }

    if (obtained.freq != 22050 || obtained.format != AUDIO_S16LSB ||
        obtained.channels != 1 || obtained.samples != 512) {
        SDL_CloseAudioDevice(dev);
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 4;
    }

    SDL_PauseAudioDevice(dev, 0);

    if (present(window, 255, 0, 0, rect_x) < 0) return 5;

    start = SDL_GetTicks();
    while (stage < 2 && SDL_GetTicks() - start < 5000) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_KEYDOWN && e.key.keysym.scancode == SDL_SCANCODE_RIGHT && stage == 0) {
                if (!SDL_GetKeyboardState(NULL)[SDL_SCANCODE_RIGHT]) return 6;
                fprintf(stdout, "SDL_KEYDOWN_RIGHT_OK\n");
                rect_x += 10;
                if (present(window, 0, 255, 0, rect_x) < 0) return 7;
                stage = 1;
            } else if (e.type == SDL_KEYUP && e.key.keysym.scancode == SDL_SCANCODE_RIGHT && stage == 1) {
                if (SDL_GetKeyboardState(NULL)[SDL_SCANCODE_RIGHT]) return 8;
                fprintf(stdout, "SDL_KEYUP_RIGHT_OK\n");
                rect_x += 10;
                if (present(window, 0, 0, 255, rect_x) < 0) return 9;
                stage = 2;
            }
        }
        SDL_Delay(10);
    }

    while (SDL_AtomicGet(&g_callback_count) < TARGET_CALLBACKS && SDL_GetTicks() - start < 5000) {
        SDL_Delay(10);
    }

    SDL_PauseAudioDevice(dev, 1);
    SDL_CloseAudioDevice(dev);
    SDL_DestroyWindow(window);
    SDL_Quit();

    if (stage != 2) return 10;
    if (SDL_AtomicGet(&g_callback_count) < TARGET_CALLBACKS) return 11;
    return 0;
}
