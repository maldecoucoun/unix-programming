/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h> // included for all kernel modules
#include <linux/kernel.h> // included for KERN_INFO
#include <linux/init.h>  // included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h> // task_struct requried for current_uid()
#include <linux/cred.h>  // for current_uid();
#include <linux/slab.h>  // for kmalloc/kfree
#include <linux/uaccess.h> // copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/mutex.h>

static DEFINE_MUTEX(lock); 

#include "maze.h"
#include <linux/random.h>

static maze_t *mazes[_MAZE_MAXUSER] = {NULL};
static int maze_count = 0;
static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static int maze_dev_open(struct inode *i, struct file *f) {
	// printk(KERN_INFO "maze: device opened.\n");
	return 0;
}

static int maze_dev_close(struct inode *i, struct file *f) {
	// pid_t process_id = (pid_t)f->private_data;
	mutex_lock(&lock);
    for (int i = 0; i < _MAZE_MAXUSER; i++) {
        if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {
            kfree(mazes[i]);
            mazes[i] = NULL; 
            break; 
        }
    }
	maze_count = 0;
	mutex_unlock(&lock);
	// printk(KERN_INFO "maze: device closed.\n");
	return 0;
}

static ssize_t maze_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off) {
	mutex_lock(&lock);
    if (*off >= _MAZE_MAXX * _MAZE_MAXY) {
		mutex_unlock(&lock);
        return 0;
    }

    bool maze_found = false;
    ssize_t bytes_copied = 0;
	char *maze_layout = NULL;

    for (int i = 0; i < _MAZE_MAXUSER; i++) {
        if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {
            maze_found = true;
			size_t maze_size = mazes[i]->w * mazes[i]->h;
			maze_layout = kmalloc(mazes[i]->w * mazes[i]->h, GFP_KERNEL);
			if (!maze_layout) {
                mutex_unlock(&lock);
                return -ENOMEM;
            }

			for(int j = 0; j < mazes[i]->h; j++){
				memcpy(maze_layout + j * mazes[i]->w, mazes[i]->blk[j], mazes[i]->w);
			}

            if (len < maze_size - (size_t)*off) {
				bytes_copied = len;
			} else {
				bytes_copied = maze_size - (size_t)*off;
			}

            // Copy 
            if (copy_to_user(buf + *off, maze_layout, mazes[i]->w * mazes[i]->h)) {
				mutex_unlock(&lock);
				kfree(maze_layout);
				return -EBUSY; 
            }

            *off += bytes_copied;
			len = bytes_copied;
            break;
        }
    }

    if (!maze_found) {
		mutex_unlock(&lock);
		kfree(maze_layout);
		return -EBADFD;
	}
	mutex_unlock(&lock);
	kfree(maze_layout);
    // printk(KERN_INFO "maze: read %zu bytes @ %llu.\n", len, *off);
	return len;
	
}

static ssize_t maze_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
    mutex_lock(&lock);
	if (len % sizeof(coord_t) != 0) {
        return -EINVAL; 
    }

    size_t num_moves = len / sizeof(coord_t);
    coord_t *moves = kmalloc(len, GFP_KERNEL); 
    if (!moves) {return -ENOMEM;}

    if (copy_from_user(moves, buf, len)) {
        kfree(moves); 
        return -EBUSY; 
	}

    bool maze_found = false;

    for (int i = 0; i < _MAZE_MAXUSER; i++) {
        if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {
            maze_found = true;
            for (size_t j = 0; j < num_moves; j++) {
                int new_x = mazes[i]->cx + moves[j].x;
                int new_y = mazes[i]->cy + moves[j].y;
                
                if (new_x >= 0 && new_x < mazes[i]->w && new_y >= 0 && new_y < mazes[i]->h && mazes[i]->blk[new_y][new_x] == 0) {
                    mazes[i]->cx = new_x; 
                    mazes[i]->cy = new_y;
                }                
            }
            break; 
        }
    }

    kfree(moves); 

    if (!maze_found) {return -EBADFD;}
	mutex_unlock(&lock);
	// printk(KERN_INFO "maze: write %zu bytes @ %llu.\n", len, *off);
	return len;
}

void dfs(int cx, int cy, maze_t *maze) {
    int directions[4][2] = {{0, 1}, {1, 0}, {0, -1}, {-1, 0}};
    int nx, ny;

    for (int i = 0; i < 4; i++) {
        int r = i + get_random_u32() % (4 - i);
        int temp_x = directions[i][0], temp_y = directions[i][1];
        directions[i][0] = directions[r][0];
        directions[i][1] = directions[r][1];
        directions[r][0] = temp_x;
        directions[r][1] = temp_y;
    }

    for (int d = 0; d < 4; d++) {
        nx = cx + directions[d][0]*2; 
        ny = cy + directions[d][1]*2;

        if (maze->blk[ny][nx] == 2) {
			int wx = cx + directions[d][0]; 
			int wy = cy + directions[d][1]; 			
			
			maze->blk[wy][wx] = 0; 
			maze->blk[ny][nx] = 0;
			dfs(nx, ny, maze); 
			
		}
    }
}

void print_maze(maze_t *maze) {
    if (!maze) {
        printk(KERN_INFO "Maze is NULL\n");
        return;
    }

    char *line = kmalloc(maze->w + 2, GFP_KERNEL);
    if (!line) {
        printk(KERN_ERR "Failed to allocate memory for maze line\n");
        return;
    }

    for (int y = 0; y < maze->h; y++) {
        for (int x = 0; x < maze->w; x++) {
            if (x == maze->sx && y == maze->sy) line[x] = 'S'; 
            else if (x == maze->ex && y == maze->ey) line[x] = 'E';
            else if (x == maze->cx && y == maze->cy) line[x] = '*'; 
            else line[x] = maze->blk[y][x] ? '#' : '.'; 
        }
        line[maze->w] = '\n';
        line[maze->w + 1] = '\0'; 
        printk(KERN_INFO "%s", line);
    }
    kfree(line);
}

void generate_maze(maze_t *maze, int width, int height) {
    int x, y;
    maze->w = width;
    maze->h = height;

    for (y = 0; y < height; y++) {
        for (x = 0; x < width; x++) {
            if (x == 0 || y == 0 || x == width-1 || y == height-1) {
                maze->blk[y][x] = 1;
            } else {
                maze->blk[y][x] = 2; 
            }
        }
    }
    // random creation
	int startx, starty, endx, endy;

    startx = get_random_u32() % (width - 2) + 1;
    starty = get_random_u32() % (height - 2) + 1;
    maze->blk[starty][startx] = 0; 

    dfs(startx, starty, maze); 
	
    do {
        endx = get_random_u32() % (width - 2) + 1;
        endy = get_random_u32() % (height - 2) + 1;
    } while ((endx == startx && endy == starty) || maze->blk[endy][endx] != 0);

	for (y = 1; y < height; y++) {
        for (x = 1; x < width; x++) {
            if (maze->blk[y][x] == 2) {
                maze->blk[y][x] = 1; 
            }
        }
    }

	maze->sx = startx;
    maze->sy = starty;
    maze->cx = startx;
    maze->cy = starty;
    maze->ex = endx;
    maze->ey = endy;
	maze->owner_pid = current->pid;
	maze->exist = true;
}

static long maze_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	// printk(KERN_INFO "maze: ioctl cmd=%u arg=%lu.\n", cmd, arg);
	// static maze_t *mazes[_MAZE_MAXUSER] = {NULL};
	
	
	mutex_lock(&lock);
	switch (cmd) {
		case MAZE_CREATE:
		{			
			int available_index = -1;
			for (int i = 0; i < _MAZE_MAXUSER; i++) {
				if (mazes[i] == NULL) {
					available_index = i;
					break;
				}
			}

			if (available_index == -1 || maze_count > 2) {
				mutex_unlock(&lock);
				return -ENOMEM;
			}

			coord_t size;
			if (copy_from_user(&size, (coord_t __user *)arg, sizeof(coord_t))) { 
				mutex_unlock(&lock);
				return -EBUSY;
			}
			
			if (size.x <= 0 || size.y <= 0 || size.x > _MAZE_MAXX || size.y > _MAZE_MAXY) { 
				mutex_unlock(&lock);
				return -EINVAL;
			}

			for (int i = 0; i < _MAZE_MAXUSER; i++) {
				if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {
					mutex_unlock(&lock);
					return -EEXIST;
				}
			}
		
			maze_t *maze = kzalloc(sizeof(maze_t), GFP_KERNEL); 
			if (!maze) {
				mutex_unlock(&lock);
				return -ENOMEM;
			}

			generate_maze(maze, size.x, size.y);
			// print_maze(maze);
			
			for (int i = 0; i < _MAZE_MAXUSER; i++) {
				// printk(KERN_INFO "in");
				if (mazes[i] == NULL) {
					mazes[i] = maze;
					// if (mazes[i] != NULL) {
					// 	printk(KERN_INFO "Maze #%d: Owner PID: %d, Size: %dx%d, Start: (%d, %d), End: (%d, %d), Current: (%d, %d), || %s\n",
					// 		i,
					// 		mazes[i]->owner_pid,
					// 		mazes[i]->w, mazes[i]->h,
					// 		mazes[i]->sx, mazes[i]->sy,
					// 		mazes[i]->ex, mazes[i]->ey,
					// 		mazes[i]->cx, mazes[i]->cy,
					// 		mazes[i]->exist ? "true" : "false");
					// } else {
					// 	printk(KERN_INFO "Maze #%d: (Empty slot)\n", i);
					// }
					maze_count++;
					break;
				}
			}
			
		}
		break;
		case MAZE_RESET:
		{
			bool maze_found = false;

			for (int i = 0; i < _MAZE_MAXUSER; i++) {
				if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {				
					mazes[i]->cx = mazes[i]->sx;
					mazes[i]->cy = mazes[i]->sy; 
					maze_found = true;
					break;
				}
			}

			if (!maze_found) {
				mutex_unlock(&lock);
				return -ENOENT;
			}
		}
		break;
		case MAZE_DESTROY:
		{
			bool maze_found = false;
			for (int i = 0; i < _MAZE_MAXUSER; i++) {
				if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {
					kfree(mazes[i]);
					mazes[i] = NULL;
					maze_found = true;
					break;
				}
			}

			if (!maze_found) {
				mutex_unlock(&lock);
				return -ENOENT;
			}
		}
		break;
		case MAZE_GETSIZE:
		{
			coord_t size;
			bool maze_found = false;

			for (int i = 0; i < _MAZE_MAXUSER; i++) {
				if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {
					size.x = mazes[i]->w;
					size.y = mazes[i]->h;
					maze_found = true;
					break;
				}
			}

			if (!maze_found) {
				mutex_unlock(&lock);
				return -ENOENT;
			}

			if (copy_to_user((coord_t __user *)arg, &size, sizeof(coord_t))) {
				mutex_unlock(&lock);
				return -EBUSY;
			}
		}
		break;
		case MAZE_MOVE:
		{
			coord_t move;
			bool maze_found = false;

			for (int i = 0; i < _MAZE_MAXUSER; i++) {
				if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {
					maze_found = true;

					if (copy_from_user(&move, (coord_t __user *)arg, sizeof(coord_t))) {
						mutex_unlock(&lock);
						return -EBUSY;
					}

					int new_x = mazes[i]->cx + move.x;
					int new_y = mazes[i]->cy + move.y;

					if (new_x >= 0 && new_x < mazes[i]->w && new_y >= 0 && new_y < mazes[i]->h && mazes[i]->blk[new_y][new_x] == 0) {
						
						mazes[i]->cx = new_x;
						mazes[i]->cy = new_y;
					}
				
					break; 
				}
			}

			if (!maze_found) {
				mutex_unlock(&lock);
				return -ENOENT;
			}
		}
		break;
		case MAZE_GETPOS:
		{
			coord_t pos;
			bool maze_found = false;

			for (int i = 0; i < _MAZE_MAXUSER; i++) {
				if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {
					pos.x = mazes[i]->cx; 
					pos.y = mazes[i]->cy;
					maze_found = true;

					if (copy_to_user((coord_t __user *)arg, &pos, sizeof(coord_t))) {				
						mutex_unlock(&lock);
						return -EBUSY;
					}

					break; 
				}
			}

			if (!maze_found) {	
				mutex_unlock(&lock);			
				return -ENOENT;
			}
		}
		break;
		case MAZE_GETSTART:
		{
			coord_t start_pos;
			bool maze_found = false;

			for (int i = 0; i < _MAZE_MAXUSER; i++) {
				if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {
		
					start_pos.x = mazes[i]->sx; 
					start_pos.y = mazes[i]->sy; 
					maze_found = true;

					if (copy_to_user((coord_t __user *)arg, &start_pos, sizeof(coord_t))) {
						mutex_unlock(&lock);
						return -EBUSY;
					}

					break;
				}
			}

			if (!maze_found) {
				mutex_unlock(&lock);
				return -ENOENT;
			}
		}
		break;
		case MAZE_GETEND:
		{
			coord_t end_pos;
			bool maze_found = false;
			for (int i = 0; i < _MAZE_MAXUSER; i++) {
				if (mazes[i] != NULL && mazes[i]->owner_pid == current->pid) {
					end_pos.x = mazes[i]->ex; 
					end_pos.y = mazes[i]->ey; 
					maze_found = true;

					if (copy_to_user((coord_t __user *)arg, &end_pos, sizeof(coord_t))) {
						mutex_unlock(&lock);
						return -EBUSY;
					}

					break; 
				}
			}
			if (!maze_found) {
				mutex_unlock(&lock);
				return -ENOENT;
			}
		}
		break;			
	}
	mutex_unlock(&lock);
	return 0;
}

static const struct file_operations maze_dev_fops = {
	.owner = THIS_MODULE,
	.open = maze_dev_open,
	.read = maze_dev_read,
	.write = maze_dev_write,
	.unlocked_ioctl = maze_dev_ioctl,
	.release = maze_dev_close
};

static int maze_proc_read(struct seq_file *m, void *v) {
	// char buf[] = "`hello, world!` in /proc.\n";
	// seq_printf(m, buf);
	mutex_lock(&lock);
	// printk(KERN_INFO "in");
	for (int i = 0; i < _MAZE_MAXUSER; i++) {
        if (mazes[i]!= NULL && mazes[i]->exist) {
            seq_printf(m, "#%02d: pid %d - [%d x %d]: (%d, %d) -> (%d, %d) @ (%d, %d)\n",
                       i, mazes[i]->owner_pid, mazes[i]->w, mazes[i]->h, 
                       mazes[i]->sx, mazes[i]->sy, mazes[i]->ex, mazes[i]->ey, 
                       mazes[i]->cx, mazes[i]->cy);
            
            for (int y = 0; y < mazes[i]->h; y++) {
                seq_printf(m, "- %03d: ", y);
                for (int x = 0; x < mazes[i]->w; x++) {
                    char c = mazes[i]->blk[y][x] ? '#' : '.'; 
                    if (x == mazes[i]->sx && y == mazes[i]->sy) c = 'S'; 
                    if (x == mazes[i]->ex && y == mazes[i]->ey) c = 'E'; 
                    if (x == mazes[i]->cx && y == mazes[i]->cy) c = '*'; 
                    seq_putc(m, c);
                }
                seq_putc(m, '\n');
            }
			seq_putc(m, '\n');
        } else {			
            seq_printf(m, "#%02d: vacancy\n\n", i);        
		}
    }
	mutex_unlock(&lock);
	return 0;
}

static int maze_proc_open(struct inode *inode, struct file *file) {
 	return single_open(file, maze_proc_read, NULL);
}

static const struct proc_ops maze_proc_fops = {
	.proc_open = maze_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *maze_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init maze_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		return -1;
	if((clazz = class_create("upclass")) == NULL)
		goto release_region;
	clazz->devnode = maze_devnode;
	if(device_create(clazz, NULL, devnum, NULL, "maze") == NULL)
		goto release_class;
	cdev_init(&c_dev, &maze_dev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;

	// create proc
	proc_create("maze", 0, NULL, &maze_proc_fops);

	printk(KERN_INFO "maze: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

	release_device:
	device_destroy(clazz, devnum);
	release_class:
	class_destroy(clazz);
	release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit maze_cleanup(void)
{
    for (int i = 0; i < _MAZE_MAXUSER; i++) {
        if (mazes[i] != NULL) {
            kfree(mazes[i]);
            mazes[i] = NULL;
        }
    }
    
	remove_proc_entry("maze", NULL);
	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "maze: cleaned up.\n");
}

module_init(maze_init);
module_exit(maze_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");