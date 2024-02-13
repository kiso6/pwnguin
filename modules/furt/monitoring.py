import psutil
from time import sleep
import random

def target_monitoring()->tuple[float,float]:
    """To be used in post exploit phase to monitor activity of \\ 
       autopwn or pwnguin tools in order to achieve stealth mode.\\
       In the following order:       (CPU usage,RAM usage)  
    """
    return (psutil.cpu_percent(),psutil.virtual_memory().percent)


def slowdown(cpu,ram):
    if (cpu > 5.0) or (ram > 25.0):
        print(f"Slow down !")
        wait = random.randint(5,10)
        sleep(wait)





import matplotlib.pyplot as plt 
stat_cpu = []
stat_ram = []
for i in range(15):
    cpu,ram = target_monitoring()
    stat_cpu.append(cpu)
    stat_ram.append(ram)
    print(f"CPU : {cpu}% | RAM : {ram}%")
    slowdown(cpu,ram)
    print("Keep going on ;-)\n")
    sleep(3)

plt.plot(stat_cpu)
plt.plot(stat_ram)
plt.show()