import psutil
 
cpu_percent = psutil.cpu_percent()
memory_percent = psutil.virtual_memory().percent
disk_percent = psutil.disk_usage('/').percent
 
print(f'CPU: {cpu_percent}%')
print(f'Memory: {memory_percent}%')
print(f'Disk: {disk_percent}%')

