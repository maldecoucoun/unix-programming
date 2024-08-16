#include "libmaze.h"
#include <stdio.h>
#include <stdbool.h>

bool solve_maze(maze_t *mz) {

    mz->blk[mz->cy][mz->cx] |= 0x80000000; // Mark the cell as visited

    // Try all directions
    int originalX = mz->cx, originalY = mz->cy;
    for (int i = 0; i < 4; i++) {
        switch (i) {
            case 0: move_up(mz); break;
            case 1: move_down(mz); break;
            case 2: move_left(mz); break;
            case 3: move_right(mz); break;
        }
        
        // Check if move changed the position
        if (mz->cx != originalX || mz->cy != originalY) {
            if (solve_maze(mz)) {
                return true;
            }
            // Reset position
            mz->cx = originalX;
            mz->cy = originalY;
        }
    }

    mz->blk[mz->cy][mz->cx] &= ~0x80000000; // Unmark the cell
    return false;
}

int 
maze_init() {
    const char *maze_file = "maze.txt";

    maze_t *mz = maze_load(maze_file);

    if (!mz) {
        fprintf(stderr, "Failed to load the maze from %s.\n", maze_file);
        return 0;  
    }

    maze_set_ptr(mz);

    mz = (maze_t *) maze_get_ptr();
    
    if (!mz) {
        fprintf(stderr, "Failed to get a valid maze pointer after setting it.\n");
        return 0; 
    }

    fprintf(stderr, "MAZE: library init - stored pointer = %p.\n", mz);
    printf("Maze dimensions: %d x %d\n", mz->w, mz->h);
    printf("Start: (%d, %d), End: (%d, %d)\n", mz->sx, mz->sy, mz->ex, mz->ey);

    if (solve_maze(mz)) {
        return 1;  
    } else {
        printf("No solution found.\n");
        return 0;  
    }
}
