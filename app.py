import streamlit as st
import pdfplumber
import imagehash
from PIL import Image
import pandas as pd
from supabase import create_client, Client
import io

# --- 1. CONFIGURATION (Must be at the very top) ---
st.set_page_config(page_title="VisionAudit Cloud", layout="wide")

# --- 2. SECURE CONNECTION ---
URL = st.secrets["SUPABASE_URL"]
KEY = st.secrets["SUPABASE_KEY"]
supabase: Client = create_client(URL, KEY)

# --- 3. SECURITY CHECK ---
def check_password():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    if not st.session_state["authenticated"]:
        st.title("🔐 VisionAudit Secure Login")
        password = st.text_input("Enter Auditor Access Key", type="password")
        if st.button("Login"):
            if password == "Audit2026!":
                st.session_state["authenticated"] = True
                st.rerun()
            else:
                st.error("Access Denied.")
        return False
    return True

if not check_password():
    st.stop()

# --- 4. MAIN INTERFACE ---
st.title("🔍 VisionAudit: Forensic Cloud Vault")

st.sidebar.header("Audit Settings")
case_ref = st.sidebar.text_input("Case Reference / Client", "General Audit")
# slider left as-is, though currently used for exact matching (hash == hash)
sensitivity = st.sidebar.slider("Match Sensitivity (0 = Exact)", 0, 15, 2)

uploaded_files = st.sidebar.file_uploader(
    "Upload Invoices (PDF) or Images", 
    type=["pdf", "png", "jpg", "jpeg"], 
    accept_multiple_files=True
)

report_data = []

if uploaded_files:
    for uploaded_file in uploaded_files:
        with st.spinner(f"Analyzing {uploaded_file.name}..."):
            current_file_images = []
            
            # PDF Processing
            if uploaded_file.type == "application/pdf":
                with pdfplumber.open(uploaded_file) as pdf:
                    for i, page in enumerate(pdf.pages):
                        # Extract images from PDF
                        for img_idx, img in enumerate(page.images):
                            try:
                                # Crop and convert to PIL Image
                                page_obj = page.crop((img["x0"], img["top"], img["x1"], img["bottom"]))
                                pil_img = page_obj.to_image(resolution=150).original
                                # Generate and stringify hash immediately
                                h_str = str(imagehash.phash(pil_img))
                                current_file_images.append({
                                    "name": f"{uploaded_file.name} (Pg {i+1}, Img {img_idx+1})", 
                                    "img": pil_img, 
                                    "hash": h_str
                                })
                            except Exception:
                                continue
            # Direct Image Processing
            else:
                pil_img = Image.open(uploaded_file)
                h_str = str(imagehash.phash(pil_img))
                current_file_images.append({"name": uploaded_file.name, "img": pil_img, "hash": h_str})

            # Cloud Database Comparison
            for item in current_file_images:
                # Query with explicit column selection to avoid KeyError
                response = supabase.table("image_inventory").select("id, file_name, case_name").eq("image_hash", item["hash"]).execute()
                
                # Check if matches exist in other files
                matches = []
                if response.data:
                    matches = [row for row in response.data if row["file_name"] != item["name"]]
                
                if matches:
                    match = matches[0]
                    st.error(f"🚨 ALERT: HISTORICAL MATCH DETECTED")
                    st.write(f"**Current Artifact:** `{item['name']}` matches `{match['file_name']}` from Case: `{match['case_name']}`")
                    st.image(item["img"], width=300)
                    st.divider()

                    report_data.append({
                        "Match Type": "Cloud/Historical",
                        "Current File": item["name"],
                        "Matched With": match["file_name"],
                        "Original Case": match["case_name"]
                    })
                else:
                    # Log unique image to the vault
                    # Explicit string conversion for image_hash to prevent APIError
                    supabase.table("image_inventory").insert({
                        "case_name": case_ref,
                        "file_name": item["name"],
                        "image_hash": str(item["hash"])
                    }).execute()

    st.success("Audit Complete. Unique images indexed in Cloud Vault.")

    if report_data:
        df = pd.DataFrame(report_data)
        csv = df.to_csv(index=False).encode('utf-8')
        st.sidebar.download_button("📥 Download Forensic Report", csv, f"Audit_{case_ref}.csv", "text/csv")

# --- 5. DANGER ZONE ---
st.sidebar.divider()
st.sidebar.subheader("⚠️ Danger Zone")
if st.sidebar.button("Clear ALL Database Records"):
    supabase.table("image_inventory").delete().neq("id", 0).execute()
    st.sidebar.warning("Cloud Vault has been wiped clean.")
    st.rerun()

if st.sidebar.button("Delete ONLY Current Case"):
    supabase.table("image_inventory").delete().eq("case_name", case_ref).execute()
    st.sidebar.info(f"Records for {case_ref} deleted.")
    st.rerun()
