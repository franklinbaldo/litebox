// Copyright (c) franklinbaldo.
// Licensed under the MIT license.

/*
 * Breakout Linux Guest Game for LiteBox on Windows Userland.
 *
 * Runs as a static musl ELF binary inside LiteBox.
 * Communicates with the Windows host purely via stdin / stdout:
 *   - stdout: Binary multiplexed stream:
 *       - Frame packet: 'F', 'R', 'A', 'M', width(u16 LE), height(u16 LE), RGB24 data
 *       - Audio packet: 'S', 'N', 'D', '0', samples(u16 LE), 16-bit mono PCM data
 *   - stdin: Binary input stream:
 *       - 'T', 'I', 'C', 'K' (4 bytes): advance one frame tick
 *       - 'K', 'E', 'Y', 'P', key_code(u8) (5 bytes): key press (1=Left, 2=Right, 3=Space/Restart, 27=Quit)
 *       - 'K', 'E', 'Y', 'R', key_code(u8) (5 bytes): key release
 *
 * All game state, physics, rendering and audio synthesis happen HERE in the guest.
 */

#include <stdint.h>
#include <unistd.h>

#define WIDTH 160
#define HEIGHT 120
#define SAMPLE_RATE 22050
#define SAMPLES_PER_FRAME (SAMPLE_RATE / 30) // ~735 samples per frame at 30 fps

#define BRICK_ROWS 4
#define BRICK_COLS 8
#define BRICK_WIDTH 16
#define BRICK_HEIGHT 6
#define BRICK_START_X 16
#define BRICK_START_Y 20

#define PADDLE_WIDTH 28
#define PADDLE_HEIGHT 4
#define PADDLE_Y (HEIGHT - 12)
#define BALL_SIZE 3

static uint8_t fb[WIDTH * HEIGHT * 3];
static int16_t audio_buf[SAMPLES_PER_FRAME];

/* Sound synthesis state */
typedef struct {
    int active;
    int frequency;
    int duration_samples;
    int current_sample;
    int waveform; /* 0: square, 1: triangle/saw, 2: noise */
} SoundTone;

static SoundTone current_sound = {0};

static void trigger_sound(int freq, int duration_samples, int waveform) {
    current_sound.active = 1;
    current_sound.frequency = freq;
    current_sound.duration_samples = duration_samples;
    current_sound.current_sample = 0;
    current_sound.waveform = waveform;
}

static void synthesize_audio(void) {
    for (int i = 0; i < SAMPLES_PER_FRAME; i++) {
        if (!current_sound.active) {
            audio_buf[i] = 0;
            continue;
        }

        int sample_val = 0;
        int period = SAMPLE_RATE / (current_sound.frequency > 0 ? current_sound.frequency : 1);
        if (period <= 0) period = 1;
        int phase = current_sound.current_sample % period;

        /* Envelope: linear decay */
        int amp = 12000 * (current_sound.duration_samples - current_sound.current_sample) / current_sound.duration_samples;
        if (amp < 0) amp = 0;

        if (current_sound.waveform == 0) {
            /* Square wave */
            sample_val = (phase < period / 2) ? amp : -amp;
        } else if (current_sound.waveform == 1) {
            /* Saw/Triangle */
            sample_val = ((phase * 2 * amp) / period) - amp;
        } else {
            /* Noise / harsh bounce */
            static uint32_t lfsr = 0xACE1u;
            lfsr = (lfsr >> 1) ^ (-(lfsr & 1u) & 0xB400u);
            sample_val = (int)(lfsr % (2 * amp + 1)) - amp;
        }

        audio_buf[i] = (int16_t)sample_val;

        current_sound.current_sample++;
        if (current_sound.current_sample >= current_sound.duration_samples) {
            current_sound.active = 0;
        }
    }
}

/* Game State */
static int key_left = 0;
static int key_right = 0;

static int paddle_x = (WIDTH - PADDLE_WIDTH) / 2;
static int ball_x = WIDTH / 2;
static int ball_y = HEIGHT / 2;
static int ball_vx = 1;
static int ball_vy = -1;

static uint8_t bricks[BRICK_ROWS][BRICK_COLS];
static int score = 0;
static int lives = 3;
static int game_over = 0;
static int game_won = 0;

static void reset_bricks(void) {
    for (int r = 0; r < BRICK_ROWS; r++) {
        for (int c = 0; c < BRICK_COLS; c++) {
            bricks[r][c] = 1;
        }
    }
}

static void init_game(void) {
    paddle_x = (WIDTH - PADDLE_WIDTH) / 2;
    ball_x = WIDTH / 2;
    ball_y = HEIGHT / 2 + 10;
    ball_vx = 1;
    ball_vy = -1;
    score = 0;
    lives = 3;
    game_over = 0;
    game_won = 0;
    reset_bricks();
}

static void update_physics(void) {
    if (game_over || game_won) return;

    /* Move paddle */
    if (key_left) {
        paddle_x -= 3;
        if (paddle_x < 2) paddle_x = 2;
    }
    if (key_right) {
        paddle_x += 3;
        if (paddle_x > WIDTH - PADDLE_WIDTH - 2) paddle_x = WIDTH - PADDLE_WIDTH - 2;
    }

    /* Move ball */
    ball_x += ball_vx;
    ball_y += ball_vy;

    /* Wall collisions */
    if (ball_x <= 2) {
        ball_x = 2;
        ball_vx = -ball_vx;
        trigger_sound(440, SAMPLE_RATE / 15, 0); /* Wall bounce: 440 Hz */
    } else if (ball_x >= WIDTH - BALL_SIZE - 2) {
        ball_x = WIDTH - BALL_SIZE - 2;
        ball_vx = -ball_vx;
        trigger_sound(440, SAMPLE_RATE / 15, 0);
    }

    if (ball_y <= 2) {
        ball_y = 2;
        ball_vy = -ball_vy;
        trigger_sound(440, SAMPLE_RATE / 15, 0);
    }

    /* Paddle collision */
    if (ball_vy > 0 &&
        ball_y + BALL_SIZE >= PADDLE_Y &&
        ball_y <= PADDLE_Y + PADDLE_HEIGHT &&
        ball_x + BALL_SIZE >= paddle_x &&
        ball_x <= paddle_x + PADDLE_WIDTH) {

        ball_y = PADDLE_Y - BALL_SIZE;
        ball_vy = -ball_vy;

        /* Influence angle based on paddle hit position */
        int hit_offset = (ball_x + BALL_SIZE / 2) - (paddle_x + PADDLE_WIDTH / 2);
        if (hit_offset < -6) ball_vx = -2;
        else if (hit_offset > 6) ball_vx = 2;
        else if (hit_offset < 0) ball_vx = -1;
        else ball_vx = 1;

        trigger_sound(587, SAMPLE_RATE / 12, 0); /* Paddle hit: 587 Hz (D5) */
    }

    /* Brick collisions */
    int remaining_bricks = 0;
    for (int r = 0; r < BRICK_ROWS; r++) {
        for (int c = 0; c < BRICK_COLS; c++) {
            if (bricks[r][c]) {
                remaining_bricks++;
                int bx = BRICK_START_X + c * BRICK_WIDTH;
                int by = BRICK_START_Y + r * BRICK_HEIGHT;

                if (ball_x + BALL_SIZE >= bx && ball_x <= bx + BRICK_WIDTH - 1 &&
                    ball_y + BALL_SIZE >= by && ball_y <= by + BRICK_HEIGHT - 1) {

                    bricks[r][c] = 0;
                    score += 10;
                    ball_vy = -ball_vy;

                    /* Pitch depends on row hit */
                    int freq = 700 + (BRICK_ROWS - r) * 120;
                    trigger_sound(freq, SAMPLE_RATE / 10, 1);
                    remaining_bricks--;
                    goto brick_hit_done;
                }
            }
        }
    }
brick_hit_done:

    if (remaining_bricks == 0) {
        game_won = 1;
        trigger_sound(880, SAMPLE_RATE / 4, 1); /* Win fanfare */
    }

    /* Ball lost below screen */
    if (ball_y > HEIGHT) {
        lives--;
        trigger_sound(180, SAMPLE_RATE / 4, 2); /* Death buzz */
        if (lives <= 0) {
            game_over = 1;
        } else {
            ball_x = paddle_x + PADDLE_WIDTH / 2;
            ball_y = PADDLE_Y - 8;
            ball_vx = (ball_vx > 0) ? 1 : -1;
            ball_vy = -1;
        }
    }
}

/* Graphics Rendering (Frame Buffer) */
static void set_pixel(int x, int y, uint8_t r, uint8_t g, uint8_t b) {
    if (x < 0 || x >= WIDTH || y < 0 || y >= HEIGHT) return;
    int idx = (y * WIDTH + x) * 3;
    fb[idx] = r;
    fb[idx + 1] = g;
    fb[idx + 2] = b;
}

static void draw_rect(int x, int y, int w, int h, uint8_t r, uint8_t g, uint8_t b) {
    for (int cy = y; cy < y + h; cy++) {
        for (int cx = x; cx < x + w; cx++) {
            set_pixel(cx, cy, r, g, b);
        }
    }
}

static void clear_screen(uint8_t r, uint8_t g, uint8_t b) {
    for (int i = 0; i < WIDTH * HEIGHT; i++) {
        fb[i * 3 + 0] = r;
        fb[i * 3 + 1] = g;
        fb[i * 3 + 2] = b;
    }
}

/* 3x5 font for simple score digits */
static const uint16_t font3x5[10] = {
    0xF6DE, 0x4924, 0xE7CE, 0xE79E, 0xB792,
    0xF39E, 0xF3DE, 0xE492, 0xF7DE, 0xF79E
};

static void draw_digit(int x, int y, int digit, uint8_t r, uint8_t g, uint8_t b) {
    if (digit < 0 || digit > 9) return;
    uint16_t glyph = (uint16_t)(font3x5[digit] << 1);
    for (int row = 0; row < 5; row++) {
        for (int col = 0; col < 3; col++) {
            if (glyph & (1 << (15 - (row * 3 + col)))) {
                set_pixel(x + col, y + row, r, g, b);
            }
        }
    }
}

static void draw_number(int x, int y, int num, uint8_t r, uint8_t g, uint8_t b) {
    if (num < 0) num = 0;
    int d1 = (num / 100) % 10;
    int d2 = (num / 10) % 10;
    int d3 = num % 10;
    if (d1 > 0) draw_digit(x, y, d1, r, g, b);
    draw_digit(x + 4, y, d2, r, g, b);
    draw_digit(x + 8, y, d3, r, g, b);
}

static void render_frame(void) {
    /* Background */
    clear_screen(12, 16, 28);

    /* Playfield border */
    draw_rect(0, 0, WIDTH, 2, 80, 80, 100);
    draw_rect(0, 0, 2, HEIGHT, 80, 80, 100);
    draw_rect(WIDTH - 2, 0, 2, HEIGHT, 80, 80, 100);

    /* Draw Bricks */
    static const uint8_t row_colors[BRICK_ROWS][3] = {
        {230, 60, 60},   /* Red */
        {240, 140, 40},  /* Orange */
        {230, 220, 50},  /* Yellow */
        {60, 200, 80}    /* Green */
    };

    for (int r = 0; r < BRICK_ROWS; r++) {
        for (int c = 0; c < BRICK_COLS; c++) {
            if (bricks[r][c]) {
                int bx = BRICK_START_X + c * BRICK_WIDTH;
                int by = BRICK_START_Y + r * BRICK_HEIGHT;
                draw_rect(bx + 1, by + 1, BRICK_WIDTH - 2, BRICK_HEIGHT - 2,
                          row_colors[r][0], row_colors[r][1], row_colors[r][2]);
            }
        }
    }

    /* Draw Paddle */
    draw_rect(paddle_x, PADDLE_Y, PADDLE_WIDTH, PADDLE_HEIGHT, 70, 160, 240);

    /* Draw Ball */
    draw_rect(ball_x, ball_y, BALL_SIZE, BALL_SIZE, 255, 255, 255);

    /* Draw Score & Lives */
    draw_number(6, 5, score, 200, 200, 200);
    for (int l = 0; l < lives; l++) {
        draw_rect(WIDTH - 12 - l * 7, 6, 4, 4, 240, 80, 80);
    }

    /* Overlays */
    if (game_over) {
        /* Red tint bar */
        draw_rect(WIDTH / 4, HEIGHT / 2 - 6, WIDTH / 2, 12, 180, 40, 40);
    } else if (game_won) {
        /* Green tint bar */
        draw_rect(WIDTH / 4, HEIGHT / 2 - 6, WIDTH / 2, 12, 40, 180, 60);
    }
}

/* Binary protocol writes */
static void write_exact(int fd, const void *data, size_t count) {
    const uint8_t *p = (const uint8_t *)data;
    while (count > 0) {
        ssize_t n = write(fd, p, count);
        if (n <= 0) break;
        p += n;
        count -= (size_t)n;
    }
}

static int read_exact(int fd, void *data, size_t count) {
    uint8_t *p = (uint8_t *)data;
    while (count > 0) {
        ssize_t n = read(fd, p, count);
        if (n <= 0) return 0;
        p += n;
        count -= (size_t)n;
    }
    return 1;
}

static void send_frame_packet(void) {
    uint8_t header[8];
    header[0] = 'F';
    header[1] = 'R';
    header[2] = 'A';
    header[3] = 'M';
    header[4] = (uint8_t)(WIDTH & 0xFF);
    header[5] = (uint8_t)((WIDTH >> 8) & 0xFF);
    header[6] = (uint8_t)(HEIGHT & 0xFF);
    header[7] = (uint8_t)((HEIGHT >> 8) & 0xFF);

    write_exact(1, header, 8);
    write_exact(1, fb, sizeof(fb));
}

static void send_audio_packet(void) {
    uint8_t header[6];
    header[0] = 'S';
    header[1] = 'N';
    header[2] = 'D';
    header[3] = '0';
    header[4] = (uint8_t)(SAMPLES_PER_FRAME & 0xFF);
    header[5] = (uint8_t)((SAMPLES_PER_FRAME >> 8) & 0xFF);

    write_exact(1, header, 6);
    write_exact(1, audio_buf, sizeof(audio_buf));
}

int main(void) {
    init_game();
    render_frame();
    send_frame_packet();
    synthesize_audio();
    send_audio_packet();

    /* Event loop driven by host TICK / KEY commands */
    while (1) {
        uint8_t cmd[4];
        if (!read_exact(0, cmd, 4)) {
            break; /* Host disconnected / closed pipe */
        }

        if (cmd[0] == 'T' && cmd[1] == 'I' && cmd[2] == 'C' && cmd[3] == 'K') {
            update_physics();
            render_frame();
            send_frame_packet();
            synthesize_audio();
            send_audio_packet();
        } else if (cmd[0] == 'K' && cmd[1] == 'E' && cmd[2] == 'Y' && cmd[3] == 'P') {
            uint8_t key_code;
            if (!read_exact(0, &key_code, 1)) break;
            if (key_code == 1) key_left = 1;
            else if (key_code == 2) key_right = 1;
            else if (key_code == 3) {
                if (game_over || game_won) init_game();
            } else if (key_code == 27) {
                break; /* Quit */
            }
        } else if (cmd[0] == 'K' && cmd[1] == 'E' && cmd[2] == 'Y' && cmd[3] == 'R') {
            uint8_t key_code;
            if (!read_exact(0, &key_code, 1)) break;
            if (key_code == 1) key_left = 0;
            else if (key_code == 2) key_right = 0;
        }
    }

    return 0;
}
