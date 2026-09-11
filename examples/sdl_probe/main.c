#include <SDL2/SDL.h>
#include <stdio.h>

int main(void) {
    SDL_version compiled;
    SDL_version linked;

    SDL_VERSION(&compiled);
    SDL_GetVersion(&linked);

    printf("=== SDL2 Probe on LiteBox ===\n");
    printf("SDL compiled version: %u.%u.%u\n", compiled.major, compiled.minor, compiled.patch);
    printf("SDL linked version: %u.%u.%u\n", linked.major, linked.minor, linked.patch);

    printf("Calling SDL_Init(0)...\n");
    if (SDL_Init(0) != 0) {
        printf("SDL_Init failed: %s\n", SDL_GetError());
        return 1;
    }
    printf("SDL_Init(0) succeeded!\n");

    SDL_Quit();
    printf("SDL_Quit finished cleanly.\n");
    printf("=== Probe complete ===\n");
    return 0;
}
