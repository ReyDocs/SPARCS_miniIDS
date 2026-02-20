import pandas as pd
import random
from datetime import datetime, timedelta

# Config
num_entries = 1000
users = ['alice', 'bob', 'charlie', 'dave']
ip_pool = ['192.168.1.' + str(i) for i in range(2, 20)] + ['10.0.0.' + str(i) for i in range(2, 20)]
status_options = ['success', 'fail']

# Generate logs
logs = []
start_time = datetime.now() - timedelta(days=1)

for _ in range(num_entries):
    timestamp = start_time + timedelta(seconds=random.randint(0, 86400))
    user = random.choice(users)
    ip = random.choice(ip_pool)
    status = random.choices(status_options, weights=[0.8,0.2])[0]
    logs.append([timestamp, user, ip, status])

# Create CSV
df_logs = pd.DataFrame(logs, columns=['timestamp', 'username', 'ip_address', 'status'])
df_logs.to_csv('simulated_auth_logs.csv', index=False)

print("simulated_auth_logs.csv created!")