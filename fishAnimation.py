import time

def animate_fish():
    frames = [
        "|                     |",
        "| >                   |",
        "| (º>                 |",
        "| (((º>               |",
        "| ><(((º>             |",
        "|   ><(((º>           |",
        "|     ><(((º>         |",
        "|       ><(((º>       |",
        "|         ><(((º>     |",
        "|           ><(((º>   |",
        "|             ><(((º> |",
        "|               ><((( |",
        "|                 ><( |",
        "|                   > |",
        "|                     |",
    ]
    for frame in frames:
        print("\r" + frame, end="")
        time.sleep(0.3)
    print()