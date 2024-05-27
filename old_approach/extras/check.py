def Central_Authority_login():
    # Get user input
    user_email = Login_emailName_entry.get()
    user_password = Login_passwordName_entry.get()
    user_type = login_role_combobox.get()

    # Create a dictionary to store login data
    login_data = {'email': user_email, 'password': user_password, 'type': user_type}

    # Serialize login data to JSON
    login_json = json.dumps(login_data)

    try:
        # Connect to the CA server
        ca_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("Connection established with the CA")
        ca_socket.connect(('127.0.0.1', 4771))  # Replace 'CA_server_IP_address' with the actual IP address

        # Send login data to the CA
        ca_socket.sendall(login_json.encode())

        # Receive authentication result from the CA
        auth_result = ca_socket.recv(1024).decode()

        # Close the socket connection
        ca_socket.close()

        # Clear the login fields
        clear_login()

        # Check authentication result
        if auth_result == 'success':
            # Determine user type and show the appropriate window
            if user_type == 'passenger':
                show_passenger_window()
            elif user_type == 'driver':
                show_driver_window()
        else:
            messagebox.showerror("Error", "Login failed. Please check your credentials.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def show_passenger_window():
    # Code to create and display the passenger window goes here
    # You can use the same GUI elements and design as the signup/signin pages

def show_driver_window():
    # Code to create and display the driver window goes here
    # You can use the same GUI elements and design as the signup/signin pages
