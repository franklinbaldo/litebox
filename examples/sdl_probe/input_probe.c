/* SDL API-only input fixture: frames advance only after right down/up events. */
#include "SDL.h"
#include <stdio.h>

static int present(SDL_Window *w, unsigned char r, unsigned char g, unsigned char b) {
    SDL_Surface *s = SDL_GetWindowSurface(w);
    SDL_Rect center = {60,45,40,30};
    if (!s || SDL_FillRect(s, NULL, SDL_MapRGB(s->format,r,g,b)) < 0 ||
        SDL_FillRect(s,&center,SDL_MapRGB(s->format,255,255,255)) < 0) return -1;
    return SDL_UpdateWindowSurface(w);
}

int main(void) {
    SDL_Window *w = SDL_CreateWindow("SDL input probe",0,0,160,120,0);
    if (!w) { fprintf(stderr,"window: %s\n",SDL_GetError()); return 1; }
    if (present(w,255,0,0)<0) return 2;
    int stage=0;
    Uint32 start=SDL_GetTicks();
    while (stage<2 && SDL_GetTicks()-start<5000) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type==SDL_KEYDOWN && e.key.keysym.scancode==SDL_SCANCODE_RIGHT && stage==0) {
                if (!SDL_GetKeyboardState(NULL)[SDL_SCANCODE_RIGHT]) return 3;
                fprintf(stdout,"SDL_KEYDOWN_RIGHT_OK\n");
                if(present(w,0,255,0)<0) return 4;
                stage=1;
            } else if(e.type==SDL_KEYUP && e.key.keysym.scancode==SDL_SCANCODE_RIGHT && stage==1) {
                if (SDL_GetKeyboardState(NULL)[SDL_SCANCODE_RIGHT]) return 5;
                fprintf(stdout,"SDL_KEYUP_RIGHT_OK\n");
                if(present(w,0,0,255)<0) return 6;
                stage=2;
            }
        }
        SDL_Delay(1);
    }
    SDL_DestroyWindow(w);
    SDL_Quit();
    return stage==2?0:7;
}
