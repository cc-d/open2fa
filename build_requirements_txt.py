#!/usr/bin/env python3
def main():
    with open('pyproject.toml', 'r') as f:
        lines = f.readlines()
    dep_sections = ['requires', 'dependencies', 'dev']
    deps = {}

    active_section = None

    for i, l in enumerate(lines):

        if active_section is None:
            for section in dep_sections:
                if l.startswith(f'{section} = ['):
                    deps[section] = []
                    active_section = section
                    break
            continue

        if active_section is None:
            continue
        elif l.strip() == ']':
            active_section = None
            continue

        dep = l.strip().replace('"', '').replace("'", '')
        if dep.endswith(','):
            dep = dep[:-1]

        deps[active_section].append(dep)

    all_deps = set()
    for section in deps:
        for dep in deps[section]:
            all_deps.add(dep)

    reqs_txt = '\n'.join(sorted(all_deps)) + '\n'

    print('Writing the following dependencies to requirements.txt:\n')
    print(reqs_txt)

    with open('requirements.txt', 'w') as f:
        f.write(reqs_txt)


if __name__ == '__main__':
    main()
