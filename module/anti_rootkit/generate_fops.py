#!/usr/bin/env python3

from typing import List, NamedTuple


class Formatter:
    s: str = ""
    indent_count: int = 0
    indent: str

    def __init__(self, indent = " " * 4) -> None:
        self.indent = indent

    def add_line(self, line):
        if len(line) > 0:
            self.s += self.indent * self.indent_count + line + "\n"
        else:
            self.s += "\n"

    def indent_add(self, i=1):
        self.indent_count += i

    def indent_sub(self, i=1):
        self.indent_count -= i

    def __iadd__(self, other):
        self.add_line(other)
        return self


class FopsPath(NamedTuple):
    path: str
    name: str


def gen_validate_fops(fops: List[str]) -> str:
    fmt: Formatter = Formatter()
    fmt += "static int validate_fops(const struct important_fops *cpy)"
    fmt += "{"
    fmt.indent_add()
    fmt += "int ret = 0;"
    fmt += ""

    for f in fops:
        fmt += f"if (fprot_validate(&cpy->{f}))"
        fmt.indent_add()
        fmt += f"ret |= FOPS_OVERWRITE_{f.upper()};"
        fmt.indent_sub()

    fmt += ""
    fmt += "return ret;"
    fmt.indent_sub()
    fmt += "}"
    fmt += ""

    return fmt.s


def gen_copy_important_fops(fops: List[str]) -> str:
    fmt: Formatter = Formatter()
    fmt += "static void copy_important_fops(struct important_fops *cpy, const struct file_operations *org)"
    fmt += "{"
    fmt.indent_add()

    for f in fops:
        fmt += f"fprot_safe_cpy(&cpy->{f}, org->{f});"
        fmt += f"cpy->{f}.addr = org->{f};"
        fmt += ""

    fmt.indent_sub()
    fmt += "}"
    fmt += ""

    return fmt.s


def gen_fops_recover(fops: List[str]) -> str:
    fmt: Formatter = Formatter()
    fmt += "static void fops_recover(const struct important_fops *cpy)"
    fmt += "{"
    fmt.indent_add()
    fmt += "pr_info(\"recovering fops\");"
    fmt += "wp_disable();"
    fmt += ""

    for f in fops:
        fmt += f"fprot_recover(&cpy->{f});"

    fmt += ""
    fmt += "wp_enable();"
    fmt.indent_sub()
    fmt += "}"
    fmt += ""

    return fmt.s


def gen_print_fops(fops: List[str]) -> str:
    fmt: Formatter = Formatter()
    fmt += "static void print_fops(const struct file_operations *fops)"
    fmt += "{"
    fmt.indent_add()
    fmt += "char buf[KSYM_NAME_LEN];"
    fmt += ""

    for f in fops:
        fmt += f"PRINT_SYMBOL(buf, fops, {f});"

    fmt.indent_sub()
    fmt += "}"
    fmt += ""

    return fmt.s


def gen_fops_print_overwrites(fops: List[str]) -> str:
    fmt: Formatter = Formatter()
    fmt += "static void fops_print_overwrites(int overwrites)"
    fmt += "{"
    fmt.indent_add()

    for f in fops:
        fmt += f"if (overwrites & FOPS_OVERWRITE_{f.upper()})"
        fmt.indent_add()
        fmt += f"pr_warn(\"'{f}' file operations overwrite detected\");"
        fmt.indent_sub()

    fmt.indent_sub()
    fmt += "}"
    fmt += ""

    return fmt.s


def gen_fops_c_header(paths: List[FopsPath]) -> str:
    fmt: Formatter = Formatter()
    fmt += "#include <linux/fs.h>"
    fmt += "#include <linux/kallsyms.h>"
    fmt += ""
    fmt += "#include \"config.h\""
    fmt += "#include \"fops.h\""
    fmt += "#include \"utils.h\""
    fmt += ""

    for p in paths:
        fmt += f"static struct important_fops org_{p.name}_fops;"

    fmt += """
#define PRINT_SYMBOL(buf, fops, name)                                          \\
    if (fops->name) {                                                          \\
        sprint_symbol(buf, (unsigned long)fops->name);                         \\
        pr_info(#name " is %s@%px", buf, fops->name);                          \\
    }
"""

    return fmt.s


def gen_fops_check() -> str:
    return """static void fops_check(const struct important_fops *cpy)
{
    int overwrites = validate_fops(cpy);
    if (!overwrites)
        return;
    pr_info("fops overwrites: %d", overwrites);
    fops_print_overwrites(overwrites);
#if RECOVER_FOPS
    fops_recover(cpy);
#endif /* RECOVER_FOPS */
}
"""


def gen_fops_init(paths: List[FopsPath]) -> str:
    fmt: Formatter = Formatter()
    fmt += "int fops_init(void)"
    fmt += "{"
    fmt.indent_add()
    fmt += "struct file_operations *fops;"
    fmt += ""

    for p in paths:
        fmt += f"fops = get_fop(\"{p.path}\");"
        fmt += "if(!fops)"
        fmt.indent_add()
        fmt += "return -ENXIO;"
        fmt.indent_sub()
        fmt += f"copy_important_fops(&org_{p.name}_fops, fops);"
        fmt += "print_fops(fops);"
        fmt += ""

    fmt += "return 0;"
    fmt.indent_sub()
    fmt += "}"
    fmt += ""

    return fmt.s


def gen_fops_check_all(paths: List[FopsPath]) -> str:
    fmt: Formatter = Formatter()
    fmt += "void fops_check_all(void)"
    fmt += "{"
    fmt.indent_add()

    for p in paths:
        fmt += f"pr_info(\"checking fops: '{p.name}'\");"
        fmt += f"fops_check(&org_{p.name}_fops);"
        fmt += ""

    fmt.indent_sub()
    fmt += "}"
    fmt += ""

    return fmt.s


def gen_fops_c(fops: List[str], paths: List[FopsPath]) -> str:
    s = ""

    s += gen_fops_c_header(paths)
    s += gen_print_fops(fops)
    s += gen_copy_important_fops(fops)
    s += gen_validate_fops(fops)
    s += gen_fops_recover(fops)
    s += gen_fops_print_overwrites(fops)
    s += gen_fops_check()
    s += gen_fops_init(paths)
    s += gen_fops_check_all(paths)

    return s

def gen_fops_h(fops: List[str], paths: List[FopsPath]) -> str:
    fmt: Formatter = Formatter()
    fmt += "#ifndef _ANTI_ROOTKIT_FOPS"
    fmt += "#define _ANTI_ROOTKIT_FOPS"
    fmt += ""
    fmt += "#include <linux/fs.h>"
    fmt += "#include \"utils.h\""
    fmt += ""

    for i ,f in enumerate(fops):
        fmt += f"#define FOPS_OVERWRITE_{f.upper()} (1 << {i})"

    fmt += ""
    fmt += "struct important_fops {"
    fmt.indent_add()

    for f in fops:
        fmt += f"struct fun_protector {f};"

    fmt.indent_sub()
    fmt += "};"

    fmt += ""
    fmt += "int fops_init(void);"
    fmt += "void fops_check_all(void);"
    fmt += ""
    
    fmt += "#endif"

    return fmt.s


if __name__ == "__main__":
    fops = ["read",  "read_iter", "iterate_shared", "llseek", "fsync"]
    paths = [FopsPath("/sys", "sysfs"),
             FopsPath("/proc", "procfs"),
             FopsPath("/", "rootfs")]

    with open("fops.c", "w+") as f:
        f.write(gen_fops_c(fops, paths))
    with open("fops.h", "w+") as f:
        f.write(gen_fops_h(fops, paths))
