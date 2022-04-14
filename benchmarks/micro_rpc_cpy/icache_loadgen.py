import sys

N = int(sys.argv[1])
M = int(sys.argv[2])
name = sys.argv[3]

print('.align 64')
print('.global ' + name)
print(name + ':')
print('    and $%d, %%rdi' % (N - 1))
print('    imul $%d, %%rdi' % (M * 64))
print('    add $' + name + ', %rdi')
print('    add $64, %rdi')
print('    jmp *%rdi\n')

for i in range(0, N):
    print('.align 64')
    print('.L%s_l%d:'  % (name, i))
    for j in range(1,M):
        #for k in range(0, 64):
        #    print('    nop')
        print('    jmp .L%s_l%d_%d' % (name, i, j))
        print('.align 64')
        print('  .L%s_l%d_%d:' % (name, i, j))

    print('    movq $%d, %%rax' % (2 * i))
    print('    ret\n')
