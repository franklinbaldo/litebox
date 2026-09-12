// Copyright (c) franklinbaldo.
// Licensed under the MIT license.

/*
 * LiteBox Real Video Backend Probe
 *
 * This application creates a 160x120 window and renders 3 distinct frames
 * (Red, Green, Blue, each with a centered white rectangle) using SDL2 surface
 * APIs. It does NOT touch file descriptors or write pixels directly.
 *
 * APIs used:
 *   - SDL_CreateWindow
 *   - SDL_GetWindowSurface
 *   - SDL_FillRect
 *   - SDL_UpdateWindowSurface
 *   - SDL_DestroyWindow
 *   - SDL_Quit
 */

#include "SDL.h"

int main(int argc, char *argv[])
{
    SDL_Window *window;
    SDL_Surface *surface;
    SDL_Rect center_rect;
    Uint32 white;
    Uint32 red;
    Uint32 green;
    Uint32 blue;

    (void)argc;
    (void)argv;

    /* Create 160x120 window (implicitly initializes video subsystem) */
    window = SDL_CreateWindow("LiteBox Video Probe",
                              SDL_WINDOWPOS_UNDEFINED,
                              SDL_WINDOWPOS_UNDEFINED,
                              160, 120, 0);
    if (!window) {
        return 1;
    }

    surface = SDL_GetWindowSurface(window);
    if (!surface) {
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 2;
    }

    /* Central rectangle (40x30 centered within 160x120) */
    center_rect.w = 40;
    center_rect.h = 30;
    center_rect.x = (160 - center_rect.w) / 2; /* 60 */
    center_rect.y = (120 - center_rect.h) / 2; /* 45 */

    white = SDL_MapRGB(surface->format, 255, 255, 255);
    red   = SDL_MapRGB(surface->format, 255, 0, 0);
    green = SDL_MapRGB(surface->format, 0, 255, 0);
    blue  = SDL_MapRGB(surface->format, 0, 0, 255);

    /* Frame 1: Red background with centered white rectangle */
    if (SDL_FillRect(surface, NULL, red) < 0 ||
        SDL_FillRect(surface, &center_rect, white) < 0 ||
        SDL_UpdateWindowSurface(window) < 0) {
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 3;
    }

    /* Frame 2: Green background with centered white rectangle */
    if (SDL_FillRect(surface, NULL, green) < 0 ||
        SDL_FillRect(surface, &center_rect, white) < 0 ||
        SDL_UpdateWindowSurface(window) < 0) {
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 4;
    }

    /* Frame 3: Blue background with centered white rectangle */
    if (SDL_FillRect(surface, NULL, blue) < 0 ||
        SDL_FillRect(surface, &center_rect, white) < 0 ||
        SDL_UpdateWindowSurface(window) < 0) {
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 5;
    }

    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
