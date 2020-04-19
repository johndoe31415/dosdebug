.code16gcc

# Open file in 32 bit mode
mov $filename, %dx
mov $0x3d00, %ax
int $0x21
push %ax

# Open it again
mov $filename, %dx
mov $0x3d00, %ax
int $0x21
push %ax

# Push this a second time so we can attempt a double close
push %ax

# Now close both files
pop %bx
mov $0x3e, %ah
int $0x21

pop %bx
mov $0x3e, %ah
int $0x21

# This close should now fail (file already closed/invalid handle)
pop %bx
mov $0x3e, %ah
int $0x21

# Exit
mov $0x4c00, %ax
int $0x21

filename:
	.string "EXAMPLE.COM"
