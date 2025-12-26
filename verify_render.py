import jinja2
import os

def test_render():
    template_path = r'c:\Users\pyroh\Desktop\Pyro Hosting\templates\manage_server.html'
    template_dir = os.path.dirname(template_path)
    
    loader = jinja2.FileSystemLoader([template_dir, os.path.dirname(template_dir)])
    env = jinja2.Environment(loader=loader)
    
    # Mocking data to trigger the problematic part
    server = {
        'id': 123,
        'name': 'Ryzen Starter',
        'price': '0.00€',
        'cpu_series': 'Ryzen',
        'status': 'Online',
        'node': 'pve',
        'os': 'Ubuntu 22.04',
        'ip': '1.2.3.4',
        'uptime_str': '1d 2h',
        'password': 'password'
    }
    
    user_session = {
        'balance': 100.0
    }
    
    try:
        template = env.get_template('manage_server.html')
        rendered = template.render(
            server=server,
            user_session=user_session,
            remaining='30d 12h',
            suspended=0,
            url_for=lambda x, **kwargs: f'/{x}'
        )
        print("Template rendered successfully!")
    except Exception as e:
        print(f"Template rendering failed: {e}")

if __name__ == "__main__":
    test_render()
