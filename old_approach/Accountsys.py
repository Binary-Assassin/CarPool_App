from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import sqlite3
import hashlib
import socket
import json
from tkinter import Toplevel, Label, Entry, Button



# ==========================
# =======Signature hash ====
# ==========================

def calculate_md5(text):
    return hashlib.md5(text.encode()).hexdigest()



Sys_Win = Tk()
Sys_Win.rowconfigure(0,weight=1)
Sys_Win.columnconfigure(0,weight=1)

height = 650
width = 1240
x = (Sys_Win.winfo_screenwidth() // 2) - (width // 2)
y = (Sys_Win.winfo_screenheight() // 4) - (height // 4)
Sys_Win.geometry('{}x{}+{}+{}'.format(width, height, x, y))


Sys_Win.title('Account System')

#navgation through pages
sign_in = Frame(Sys_Win)
sign_up = Frame(Sys_Win)

for frame in (sign_in,sign_up):
    frame.grid(row=0,column=0,sticky='nsew')

def show_frame(frame):
    frame.tkraise()

show_frame(sign_up)



## ==============================================
#  ====== registration up page code here ========
# ===============================================


# signup text variables
FirstName = StringVar()
LastName = StringVar()
Email = StringVar()
Password = StringVar()
ConfirmPassword = StringVar()
selected_role = StringVar()


sign_up.configure(bg="#525561")

# ================Background Image ====================
backgroundImage = PhotoImage(file="assets\\image_1.png")
bg_image = Label(
    sign_up,
    image=backgroundImage,
    bg="#525561"
)
bg_image.place(x=120, y=28)

# ================ Header Text Left ====================
headerText_image_left = PhotoImage(file="assets\\headerText_image.png")
headerText_image_label1 = Label(
    bg_image,
    image=headerText_image_left,
    bg="#272A37"
)
headerText_image_label1.place(x=60, y=45)

headerText1 = Label(
    bg_image,
    text="Car Pooling System",
    fg="#FFFFFF",
    font=("yu gothic ui bold", 20 * -1),
    bg="#272A37"
)
headerText1.place(x=110, y=45)

# ================ Header Text Right ====================
headerText_image_right = PhotoImage(file="assets\\headerText_image.png")
headerText_image_label2 = Label(
    bg_image,
    image=headerText_image_right,
    bg="#272A37"
)
headerText_image_label2.place(x=400, y=45)

headerText2 = Label(
    bg_image,
    anchor="nw",
    text="Registration Page",
    fg="#FFFFFF",
    font=("yu gothic ui Bold", 20 * -1),
    bg="#272A37"
)
headerText2.place(x=450, y=45)

# ================ CREATE ACCOUNT HEADER ====================
createAccount_header = Label(
    bg_image,
    text="Create new account",
    fg="#FFFFFF",
    font=("yu gothic ui Bold", 28 * -1),
    bg="#272A37"
)
createAccount_header.place(x=75, y=121)

# ================ ALREADY HAVE AN ACCOUNT TEXT ====================
text = Label(
    bg_image,
    text="Already a member?",
    fg="#FFFFFF",
    font=("yu gothic ui Regular", 15 * -1),
    bg="#272A37"
)
text.place(x=75, y=187)

# ================ GO TO LOGIN ====================
switchLogin = Button(
    bg_image,
    text="Login",
    fg="#206DB4",
    font=("yu gothic ui Bold", 15 * -1),
    bg="#272A37",
    bd=0,
    cursor="hand2",
    activebackground="#272A37",
    activeforeground="#ffffff",
    command=lambda : show_frame(sign_in)
)
switchLogin.place(x=230, y=185, width=50, height=35)

# ================ First Name Section ====================
firstName_image = PhotoImage(file="assets\\input_img.png")
firstName_image_Label = Label(
    bg_image,
    image=firstName_image,
    bg="#272A37"
)
firstName_image_Label.place(x=80, y=242)

firstName_text = Label(
    firstName_image_Label,
    text="First name",
    fg="#FFFFFF",
    font=("yu gothic ui SemiBold", 13 * -1),
    bg="#3D404B"
)
firstName_text.place(x=25, y=0)

firstName_icon = PhotoImage(file="assets\\name_icon.png")
firstName_icon_Label = Label(
    firstName_image_Label,
    image=firstName_icon,
    bg="#3D404B"
)
firstName_icon_Label.place(x=159, y=15)

firstName_entry = Entry(
    firstName_image_Label,
    bd=0,
    bg="#3D404B",
    highlightthickness=0,
    font=("yu gothic ui SemiBold", 16 * -1),
    textvariable=FirstName
)
firstName_entry.place(x=8, y=17, width=140, height=27)


# ================ Last Name Section ====================
lastName_image = PhotoImage(file="assets\\input_img.png")
lastName_image_Label = Label(
    bg_image,
    image=lastName_image,
    bg="#272A37"
)
lastName_image_Label.place(x=293, y=242)

lastName_text = Label(
    lastName_image_Label,
    text="Last name",
    fg="#FFFFFF",
    font=("yu gothic ui SemiBold", 13 * -1),
    bg="#3D404B"
)
lastName_text.place(x=25, y=0)

lastName_icon = PhotoImage(file="assets\\name_icon.png")
lastName_icon_Label = Label(
    lastName_image_Label,
    image=lastName_icon,
    bg="#3D404B"
)
lastName_icon_Label.place(x=159, y=15)

lastName_entry = Entry(
    lastName_image_Label,
    bd=0,
    bg="#3D404B",
    highlightthickness=0,
    font=("yu gothic ui SemiBold", 16 * -1),
    textvariable= LastName
)
lastName_entry.place(x=8, y=17, width=140, height=27)


# ================ Drop Down for Passenger/Driver ====================
selected_role.set("Passenger")  # Default value

roles = ["Passenger", "Driver"]

role_combobox = ttk.Combobox(
    bg_image,
    textvariable=selected_role,
    values=roles,
    state="readonly",  # Ensures the user cannot type in a custom value
    font=("yu gothic ui SemiBold", 12),
    background="#1E90FF",
)
role_combobox.place(x=570, y=242, width=140, height=30)



# ================ Email Name Section ====================
emailName_image = PhotoImage(file="assets\\email.png")
emailName_image_Label = Label(
    bg_image,
    image=emailName_image,
    bg="#272A37"
)
emailName_image_Label.place(x=80, y=311)

emailName_text = Label(
    emailName_image_Label,
    text="Email account",
    fg="#FFFFFF",
    font=("yu gothic ui SemiBold", 13 * -1),
    bg="#3D404B"
)
emailName_text.place(x=25, y=0)

emailName_icon = PhotoImage(file="assets\\email-icon.png")
emailName_icon_Label = Label(
    emailName_image_Label,
    image=emailName_icon,
    bg="#3D404B"
)
emailName_icon_Label.place(x=370, y=15)

emailName_entry = Entry(
    emailName_image_Label,
    bd=0,
    bg="#3D404B",
    highlightthickness=0,
    font=("yu gothic ui SemiBold", 16 * -1),
    textvariable=Email
)
emailName_entry.place(x=8, y=17, width=354, height=27)


# ================ Password Name Section ====================
passwordName_image = PhotoImage(file="assets\\input_img.png")
passwordName_image_Label = Label(
    bg_image,
    image=passwordName_image,
    bg="#272A37"
)
passwordName_image_Label.place(x=80, y=380)

passwordName_text = Label(
    passwordName_image_Label,
    text="Password",
    fg="#FFFFFF",
    font=("yu gothic ui SemiBold", 13 * -1),
    bg="#3D404B"
)
passwordName_text.place(x=25, y=0)

passwordName_icon = PhotoImage(file="assets\\pass-icon.png")
passwordName_icon_Label = Label(
    passwordName_image_Label,
    image=passwordName_icon,
    bg="#3D404B"
)
passwordName_icon_Label.place(x=159, y=15)

passwordName_entry = Entry(
    passwordName_image_Label,
    bd=0,
    bg="#3D404B",
    highlightthickness=0,
    font=("yu gothic ui SemiBold", 16 * -1),
    textvariable=Password
)
passwordName_entry.place(x=8, y=17, width=140, height=27)


# ================ Confirm Password Name Section ====================
confirm_passwordName_image = PhotoImage(file="assets\\input_img.png")
confirm_passwordName_image_Label = Label(
    bg_image,
    image=confirm_passwordName_image,
    bg="#272A37"
)
confirm_passwordName_image_Label.place(x=293, y=380)

confirm_passwordName_text = Label(
    confirm_passwordName_image_Label,
    text="Confirm Password",
    fg="#FFFFFF",
    font=("yu gothic ui SemiBold", 13 * -1),
    bg="#3D404B"
)
confirm_passwordName_text.place(x=25, y=0)

confirm_passwordName_icon = PhotoImage(file="assets\\pass-icon.png")
confirm_passwordName_icon_Label = Label(
    confirm_passwordName_image_Label,
    image=confirm_passwordName_icon,
    bg="#3D404B"
)
confirm_passwordName_icon_Label.place(x=159, y=15)

confirm_passwordName_entry = Entry(
    confirm_passwordName_image_Label,
    bd=0,
    bg="#3D404B",
    highlightthickness=0,
    font=("yu gothic ui SemiBold", 16 * -1),
    textvariable=ConfirmPassword
)
confirm_passwordName_entry.place(x=8, y=17, width=140, height=27)

# =============== Submit Button ====================
submit_buttonImage = PhotoImage(
    file="assets\\button_1.png")
submit_button = Button(
    bg_image,
    image=submit_buttonImage,
    borderwidth=0,
    highlightthickness=0,
    relief="flat",
    activebackground="#272A37",
    cursor="hand2",
    command=lambda : signup()
)
submit_button .place(x=130, y=460, width=333, height=65)

# ================ Header Text Down ====================
headerText_image_down = PhotoImage(file="assets\\headerText_image.png")
headerText_image_label3 = Label(
    bg_image,
    image=headerText_image_down,
    bg="#272A37"
)
headerText_image_label3.place(x=650, y=530)

headerText3 = Label(
    bg_image,
    text="Powered by Fast Nu",
    fg="#FFFFFF",
    font=("yu gothic ui bold", 20 * -1),
    bg="#272A37"
)
headerText3.place(x=700, y=530)


# clear sign up fields
def clear():
    LastName.set("")
    FirstName.set("")
    Password.set("")
    ConfirmPassword.set("")
    Email.set("")



# ======================================
# ======= database connection setup ====
#=========================================


def signup():
    if firstName_entry.get() == "" or lastName_entry.get() == "" or passwordName_entry.get() == "" or emailName_entry.\
            get() == "" or confirm_passwordName_entry.get() == "":
        messagebox.showerror("Error , all Fields are required")

    elif passwordName_entry.get() != confirm_passwordName_entry.get():
        messagebox.showerror("Error, Password Didnt match")

    else:

        try:
            connection = sqlite3.connect("Database/AccountSystem.db")
            cur = connection.cursor()
            user_id = emailName_entry.get()
            uni_id = user_id.split('@')[0]

            # Concatenate email and password
            password = passwordName_entry.get() 
            data = user_id + password
            # Calculate MD5 hash
            hash_sign = calculate_md5(data)

            # Get the selected role from the combobox
            selected_role = role_combobox.get()

            cur.execute("INSERT INTO AccountDB (FirstName, LastName, Email, Password, Type, UniID, Sign_MD5, Ratings) VALUES (?,?,?,?,?,?,?,?)",
                        (firstName_entry.get(), lastName_entry.get(), emailName_entry.get(), passwordName_entry.get(), selected_role, uni_id, hash_sign, 0.4))
            
            # Commit changes to the database
            connection.commit()
            connection.close()
            clear()

            messagebox.showinfo("Success", "Account created successfully")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")


## ==============================================
#  ====== login page code here ========
# ===============================================

email = StringVar()
password = StringVar()
selected_role = StringVar()

sign_in.configure(bg="#525561")

# ================Background Image ====================
Login_backgroundImage = PhotoImage(file="assets\\image_1.png")
bg_imageLogin = Label(
    sign_in,
    image=Login_backgroundImage,
    bg="#525561"
)
bg_imageLogin.place(x=120, y=28)

# ================ Header Text Left ====================
Login_headerText_image_left = PhotoImage(file="assets\\headerText_image.png")
Login_headerText_image_label1 = Label(
    bg_imageLogin,
    image=Login_headerText_image_left,
    bg="#272A37"
)
Login_headerText_image_label1.place(x=60, y=45)

Login_headerText1 = Label(
    bg_imageLogin,
    text="Car Pooling System",
    fg="#FFFFFF",
    font=("yu gothic ui bold", 20 * -1),
    bg="#272A37"
)
Login_headerText1.place(x=110, y=45)

# ================ Header Text Right ====================
Login_headerText_image_right = PhotoImage(file="assets\\headerText_image.png")
Login_headerText_image_label2 = Label(
    bg_imageLogin,
    image=Login_headerText_image_right,
    bg="#272A37"
)
Login_headerText_image_label2.place(x=400, y=45)

Login_headerText2 = Label(
    bg_imageLogin,
    anchor="nw",
    text="Login Page",
    fg="#FFFFFF",
    font=("yu gothic ui Bold", 20 * -1),
    bg="#272A37"
)
Login_headerText2.place(x=450, y=45)

# ================ LOGIN TO ACCOUNT HEADER ====================
loginAccount_header = Label(
    bg_imageLogin,
    text="Login to continue",
    fg="#FFFFFF",
    font=("yu gothic ui Bold", 28 * -1),
    bg="#272A37"
)
loginAccount_header.place(x=75, y=121)

# ================ NOT A MEMBER TEXT ====================
loginText = Label(
    bg_imageLogin,
    text="Not a member?",
    fg="#FFFFFF",
    font=("yu gothic ui Regular", 15 * -1),
    bg="#272A37"
)
loginText.place(x=75, y=187)

# ================ GO TO SIGN UP ====================
switchSignup = Button(
    bg_imageLogin,
    text="Sign Up",
    fg="#206DB4",
    font=("yu gothic ui Bold", 15 * -1),
    bg="#272A37",
    bd=0,
    cursor="hand2",
    activebackground="#272A37",
    activeforeground="#ffffff",
    command=lambda : show_frame(sign_up)
)
switchSignup.place(x=220, y=185, width=70, height=35)


# ================ Drop Down for Passenger/Driver ====================

selected_role.set("Passenger")  # Default value

login_roles = ["Passenger", "Driver"]

login_role_combobox = ttk.Combobox(
    bg_imageLogin,
    textvariable=selected_role,
    values=login_roles,  # Use login_roles instead of roles
    state="readonly",  # Ensures the user cannot type in a custom value
    font=("yu gothic ui SemiBold", 12),
    background="#1E90FF",
)
login_role_combobox.place(x=570, y=240, width=140, height=30)


# ================ Email Name Section ====================
Login_emailName_image = PhotoImage(file="assets\\email.png")
Login_emailName_image_Label = Label(
    bg_imageLogin,
    image=Login_emailName_image,
    bg="#272A37"
)
Login_emailName_image_Label.place(x=76, y=242)

Login_emailName_text = Label(
    Login_emailName_image_Label,
    text="Email account",
    fg="#FFFFFF",
    font=("yu gothic ui SemiBold", 13 * -1),
    bg="#3D404B"
)
Login_emailName_text.place(x=25, y=0)

Login_emailName_icon = PhotoImage(file="assets\\email-icon.png")
Login_emailName_icon_Label = Label(
    Login_emailName_image_Label,
    image=Login_emailName_icon,
    bg="#3D404B"
)
Login_emailName_icon_Label.place(x=370, y=15)

Login_emailName_entry = Entry(
    Login_emailName_image_Label,
    bd=0,
    bg="#3D404B",
    highlightthickness=0,
    font=("yu gothic ui SemiBold", 16 * -1),
    textvariable=email
)
Login_emailName_entry.place(x=8, y=17, width=354, height=27)



# ================ Password Name Section ====================
Login_passwordName_image = PhotoImage(file="assets\\email.png")
Login_passwordName_image_Label = Label(
    bg_imageLogin,
    image=Login_passwordName_image,
    bg="#272A37"
)
Login_passwordName_image_Label.place(x=80, y=330)

Login_passwordName_text = Label(
    Login_passwordName_image_Label,
    text="Password",
    fg="#FFFFFF",
    font=("yu gothic ui SemiBold", 13 * -1),
    bg="#3D404B"
)
Login_passwordName_text.place(x=25, y=0)

Login_passwordName_icon = PhotoImage(file="assets\\pass-icon.png")
Login_passwordName_icon_Label = Label(
    Login_passwordName_image_Label,
    image=Login_passwordName_icon,
    bg="#3D404B"
)
Login_passwordName_icon_Label.place(x=370, y=15)

Login_passwordName_entry = Entry(
    Login_passwordName_image_Label,
    bd=0,
    bg="#3D404B",
    highlightthickness=0,
    font=("yu gothic ui SemiBold", 16 * -1),
    textvariable=password
)
Login_passwordName_entry.place(x=8, y=17, width=354, height=27)



# =============== Submit Button ====================
Login_button_image_1 = PhotoImage(
    file="assets\\button_1.png")
Login_button_1 = Button(
    bg_imageLogin,
    image=Login_button_image_1,
    borderwidth=0,
    highlightthickness=0,
    command=lambda: Central_Authority_login(),
    relief="flat",
    activebackground="#272A37",
    cursor="hand2",
)
Login_button_1.place(x=120, y=445, width=333, height=65)

# ================ Header Text Down ====================
Login_headerText_image_down = PhotoImage(file="assets\\headerText_image.png")
Login_headerText_image_label3 = Label(
    bg_imageLogin,
    image=Login_headerText_image_down,
    bg="#272A37"
)
Login_headerText_image_label3.place(x=650, y=530)

Login_headerText3 = Label(
    bg_imageLogin,
    text="Powered by Fast Nu",
    fg="#FFFFFF",
    font=("yu gothic ui bold", 20 * -1),
    bg="#272A37"
)
Login_headerText3.place(x=700, y=530)




#=============== clear login fields =================
def clear_login():
    email.set("")
    password.set("")


# ============ -- Connection with the Central Authority -- ===================

ca_socket = None  
RESPONSE_LOGIN = 'login'
RESPONSE_PASSENGER_DATA = 'passenger_data'
RESPONSE_DRIVER_DATA = 'driver_data'

def Central_Authority_login():
    global ca_socket  # Access the global socket variable

    # Get user input
    user_email = Login_emailName_entry.get()
    user_password = Login_passwordName_entry.get()
    user_type = login_role_combobox.get()
    uni_id = user_email.split('@')[0]

    # Create a dictionary to store login data
    login_data = {'email': user_email, 'password': user_password, 'type': user_type, 'response_type': RESPONSE_LOGIN}

    # Serialize login data to JSON
    login_json = json.dumps(login_data)

    try:
        if not ca_socket:
            # Connect to the CA server if the socket is not already created
            ca_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ca_socket.connect(('127.0.0.1', 4771))  # Replace 'CA_server_IP_address' with the actual IP address

        # Send login data to the CA
        ca_socket.sendall(login_json.encode())

        # Receive authentication result from the CA
        auth_response = ca_socket.recv(1024).decode()
        auth_response_data = json.loads(auth_response)

        clear_login()
        # Check authentication result
        if auth_response_data.get('response_type') == RESPONSE_LOGIN:
            if auth_response_data.get('status') == 'success':
                messagebox.showinfo("Success", "Login successful")
                # Redirect to the next page or perform necessary actions upon successful login
                if user_type == 'Passenger':
                    show_Passenger_window(uni_id)
                elif user_type == 'Driver':
                    show_Driver_window(uni_id)
            else:
                messagebox.showerror("Error", "Login failed. Please check your credentials.")
                ca_socket.close()
        else:
            messagebox.showerror("Error", "Unexpected response from server.")
            ca_socket.close()
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def show_Passenger_window(uni_id):
    passenger_window = Toplevel(Sys_Win)
    passenger_window.title("Passenger Window")
    passenger_window.geometry("600x400")

    # Passenger window GUI elements
    passenger_label = Label(passenger_window, text="Welcome, Passenger!", font=("Helvetica", 16))
    passenger_label.pack(pady=20)

    # Source input
    source_label = Label(passenger_window, text="Source:")
    source_label.pack()
    source_entry = Entry(passenger_window)
    source_entry.pack()

    # Destination input
    destination_label = Label(passenger_window, text="Destination:")
    destination_label.pack()
    destination_entry = Entry(passenger_window)
    destination_entry.pack()

    # Submit button
    submit_button = Button(passenger_window, text="Submit", command=lambda: submit_passenger_data(uni_id, source_entry.get(), destination_entry.get()))
    submit_button.pack(pady=20)

    # Text box to display available drivers
    drivers_textbox = Text(passenger_window, height=10, width=50)
    drivers_textbox.pack(pady=20)

    #Function to update the textbox with available drivers
    def update_drivers_list(drivers):
        drivers_textbox.delete(1.0, END)
        for driver in drivers:
            drivers_textbox.insert(END, f"Driver ID: {driver['driver_id']}\n")
            drivers_textbox.insert(END, f"Source: {driver['source']}\n")
            drivers_textbox.insert(END, f"Destination: {driver['destination']}\n")
            drivers_textbox.insert(END, f"Fare: {driver['fare']}\n")
            drivers_textbox.insert(END, f"Seats available: {driver['seats_available']}\n")
            drivers_textbox.insert(END, f"Departure time: {driver['departure_time']}\n\n")

    # Function to submit passenger data and receive drivers list
    def submit_passenger_data(uni_id, source, destination):
        # Serialize input data into JSON format
        passenger_data = {
            "response_type": RESPONSE_PASSENGER_DATA,
            "type": "Passenger",
            "passenger_id": uni_id,
            "source": source,
            "destination": destination
        }
        passenger_json = json.dumps(passenger_data)

        # Send passenger data to the Central Authority (CA)
        ca_socket.sendall(passenger_json.encode())

        # Receive drivers list from CA
        response_data = b""
        while True:
            chunk = ca_socket.recv(4096)
            if not chunk:
                break
            response_data += chunk

        # Decode JSON data
        response_json = response_data.decode()

        # Parse JSON data
        response_dict = json.loads(response_json)

        #Extract passenger ID and available drivers from the response
        
        passenger_id = response_dict['data']['passenger_id']
        available_drivers = response_dict['data']['available_drivers']

        #Update the textbox with available drivers
        update_drivers_list(available_drivers)


def show_Driver_window(uni_id):
    driver_window = Toplevel(Sys_Win)
    driver_window.title("Driver Window")
    driver_window.geometry("600x400")

    # Driver window GUI elements
    driver_label = Label(driver_window, text="Welcome, Driver!", font=("Helvetica", 16))
    driver_label.pack(pady=20)

    # Source input
    source_label = Label(driver_window, text="Source:")
    source_label.pack()
    source_entry = Entry(driver_window)
    source_entry.pack()

    # Destination input
    destination_label = Label(driver_window, text="Destination:")
    destination_label.pack()
    destination_entry = Entry(driver_window)
    destination_entry.pack()

    # Fare input
    fare_label = Label(driver_window, text="Fare:")
    fare_label.pack()
    fare_entry = Entry(driver_window)
    fare_entry.pack()

    # Seats input
    seats_label = Label(driver_window, text="Seats available:")
    seats_label.pack()
    seats_entry = Entry(driver_window)
    seats_entry.pack()

    # Time input
    time_label = Label(driver_window, text="Departure time:")
    time_label.pack()
    time_entry = Entry(driver_window)
    time_entry.pack()

    # Submit button
    submit_button = Button(driver_window, text="Submit", command=lambda: submit_driver_data(uni_id, source_entry.get(), destination_entry.get(), fare_entry.get(), seats_entry.get(), time_entry.get()))
    submit_button.pack(pady=20)

def submit_driver_data(uni_id, source, destination, fare, seats, time):
    # Serialize input data into JSON format
    
    driver_data = {
        "response_type": RESPONSE_DRIVER_DATA,
        "driver_id": uni_id,
        "source": source,
        "destination": destination,
        "fare": fare,
        "seats_available": seats,
        "departure_time": time
    }
    driver_json = json.dumps(driver_data)

    # Send driver data to the Central Authority (CA)
    ca_socket.sendall(driver_json.encode())



# ================ Forgot Password ====================
forgotPassword = Button(
    bg_imageLogin,
    text="Forgot Password",
    fg="#206DB4",
    font=("yu gothic ui Bold", 15 * -1),
    bg="#272A37",
    bd=0,
    activebackground="#272A37",
    activeforeground="#ffffff",
    cursor="hand2",
    command=lambda: forgot_password(),
)
forgotPassword.place(x=210, y=400, width=150, height=35)


def forgot_password():

    win = Toplevel()
    window_width = 350
    window_height = 350
    screen_width = win.winfo_screenwidth()
    screen_height = win.winfo_screenheight()
    position_top = int(screen_height / 4 - window_height / 4)
    position_right = int(screen_width / 2 - window_width / 2)
    win.geometry(f'{window_width}x{window_height}+{position_right}+{position_top}')

    win.title('Forgot Password')
    # win.iconbitmap('images\\aa.ico')
    win.configure(background='#272A37')
    win.resizable(False, False)

    # ====== Email ====================
    email_entry3 = Entry(win, bg="#3D404B", font=("yu gothic ui semibold", 12), highlightthickness=1,
                         bd=0)
    email_entry3.place(x=40, y=80, width=256, height=50)
    email_entry3.config(highlightbackground="#3D404B", highlightcolor="#206DB4")
    email_label3 = Label(win, text='• Email', fg="#FFFFFF", bg='#272A37',
                         font=("yu gothic ui", 11, 'bold'))
    email_label3.place(x=40, y=50)

    # ====  New Password ==================
    new_password_entry = Entry(win, bg="#3D404B", font=("yu gothic ui semibold", 12), show='•', highlightthickness=1,
                               bd=0)
    new_password_entry.place(x=40, y=180, width=256, height=50)
    new_password_entry.config(highlightbackground="#3D404B", highlightcolor="#206DB4")
    new_password_label = Label(win, text='• New Password', fg="#FFFFFF", bg='#272A37',
                               font=("yu gothic ui", 11, 'bold'))
    new_password_label.place(x=40, y=150)

    # ======= Update password Button ============
    update_pass = Button(win, fg='#f8f8f8', text='Update Password', bg='#1D90F5', font=("yu gothic ui", 12, "bold"),
                         cursor='hand2', relief="flat", bd=0, highlightthickness=0, activebackground="#1D90F5")
    update_pass.place(x=40, y=260, width=256, height=45)






Sys_Win.resizable(False,False)
Sys_Win.mainloop()