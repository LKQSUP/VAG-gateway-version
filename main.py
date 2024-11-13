import streamlit as st
import logging
from openobd import OpenOBD, BusConfiguration, CanBus, CanProtocol, CanBitRate, TransceiverSpeed, IsotpChannel, Padding, IsotpSocket, ServiceResult, Result, StreamHandler, SessionTokenHandler


log_file_path = "responses_log.txt"
sfd2_log_file_path = "sfd2_log.txt"

# Configure logging
logging.basicConfig(level=logging.INFO)


# Function to log data to a file
def log_response(data, filepath=log_file_path):
    with open(filepath, "a") as log_file:
        log_file.write(f"{data}\n\n")


# Function to retrieve the last 3 car data entries from the log file
def get_last_3_logs():
    try:
        with open(log_file_path, "r") as log_file:
            lines = log_file.readlines()

        entries = "".join(lines).strip().split("\n\n")
        return entries[-3:]
    except FileNotFoundError:
        return ["No previous data available."]


# Function to retrieve all log data
def get_all_logs():
    try:
        with open(log_file_path, "r") as log_file:
            all_logs = log_file.read()
        return all_logs.split("\n\n")
    except FileNotFoundError:
        return ["No log data available."]


# Function to start an OBD session
def initialize_obd_session(ticket_id):
    openobd = OpenOBD()
    try:
        session = openobd.start_session_on_ticket(ticket_id)
        SessionTokenHandler(session)
        return session
    except Exception as e:
        logging.error(f"Failed to start session: {e}")
        return None


# Function to configure buses
def configure_buses(session):
    bus_configs = [
        BusConfiguration(
            bus_name="bus_6_14",
            can_bus=CanBus(
                pin_plus=6,
                pin_min=14,
                can_protocol=CanProtocol.CAN_PROTOCOL_ISOTP,
                can_bit_rate=CanBitRate.CAN_BIT_RATE_500,
                transceiver=TransceiverSpeed.TRANSCEIVER_SPEED_HIGH)),
        BusConfiguration(
            bus_name="bus_3_11",
            can_bus=CanBus(
                pin_plus=3,
                pin_min=11,
                can_protocol=CanProtocol.CAN_PROTOCOL_ISOTP,
                can_bit_rate=CanBitRate.CAN_BIT_RATE_500,
                transceiver=TransceiverSpeed.TRANSCEIVER_SPEED_HIGH))
    ]
    stream = StreamHandler(session.configure_bus)
    stream.send_and_close(bus_configs)


# Function to process each request and check for SFD2
def process_request(gtw, name, command):
    try:
        response = gtw.request(command, tries=2, timeout=5)
        if response:
            response_hex = response[6:]
            try:
                data = bytes.fromhex(response_hex).decode("utf-8")
                result_str = f"{name}: {data}"
                log_response(result_str)

                sfd2_keywords = ["UNECE", "UN-ECE", "ECE"]
                sfd2_factory_parts = [
                    "3Q0907530BB", "1EE937012D", "1EE937012B", "4KL907468Q"
                ]

                if name == "ECU Type" and any(keyword in data for keyword in sfd2_keywords) or \
                   name == "Factory Part Number" and data in sfd2_factory_parts:
                    return data, True  # SFD2 detected
                else:
                    return data, False
            except UnicodeDecodeError:
                log_response(
                    f"{name}: (Cannot decode to UTF-8) {response_hex}")
    except Exception as e:
        logging.error(f"Request failed: {e}")
        log_response(f"Request failed: {e}")

    return "Request failed", False


# Function to save SFD2 data to the SFD2 log file
def save_sfd2_log(data):
    log_response(data, filepath=sfd2_log_file_path)


# Main function to run the OBD script and check for SFD2
def run_obd_script(ticket_id):
    responses = []
    sfd2_detected = False
    sfd2_data = {}

    session = initialize_obd_session(ticket_id)
    if not session:
        return "Invalid Ticket ID or session could not be started.", False

    configure_buses(session)

    gtw_channel = IsotpChannel(bus_name="bus_6_14",
                               request_id=0x710,
                               response_id=0x77A,
                               padding=Padding.PADDING_ENABLED)
    gtw = IsotpSocket(session, gtw_channel)

    try:
        responses.append(f"Response: {gtw.request('1003', silent=True)}")
        log_response(f"Response: {responses[-1]}")

        requests = {
            "VIN": "22F190",
            "Factory Part Number": "22F187",
            "ECU Type": "22F19E",
        }
        for name, command in requests.items():
            data, is_sfd2 = process_request(gtw, name, command)
            responses.append(f"{name}: {data}")
            sfd2_data[name] = data

            if is_sfd2:
                sfd2_detected = True

    finally:
        gtw.stop_stream()

    session.finish(ServiceResult(result=[Result.RESULT_SUCCESS]))

    if sfd2_detected:
        save_sfd2_log(" | ".join(f"{k}: {v}" for k, v in sfd2_data.items()))
        return responses, True
    else:
        log_response(" | ".join(f"{k}: {v}" for k, v in sfd2_data.items()))
        return responses, False


# Streamlit Interface
st.title("Check Vehicle Gateway SFD Status")

ticket_id = st.text_input("Enter Ticket ID:")

if st.button("Run Script"):
    if ticket_id:
        responses, sfd2_detected = run_obd_script(ticket_id)
        if isinstance(responses, str):
            # Display the error message in red if the ticket ID is invalid
            st.error(responses)
        else:
            st.write("### Results:")
            for response in responses:
                st.write(response)

            # Display SFD2 status message in red if detected, green otherwise
            if sfd2_detected:
                st.error("The vehicle has SFD2")
            else:
                st.success("The vehicle has no SFD2")
    else:
        st.error("Please enter a valid Ticket ID")

st.write("### View Logs")
log_option = st.selectbox("Select Log to View",
                          ["Last 3 Entries", "All Entries"])

if log_option == "Last 3 Entries":
    last_3_logs = get_last_3_logs()
    st.write("### Last 3 Entries:")
    for log in last_3_logs:
        st.write(log)
elif log_option == "All Entries":
    all_logs = get_all_logs()
    st.write("### All Entries:")
    for log in all_logs:
        st.write(log)
