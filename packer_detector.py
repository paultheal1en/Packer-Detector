import os
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
import threading
import re
from PIL import Image, ImageTk
import webbrowser
import shutil
import hashlib
import datetime
import stat
import json

class PackerDetectorApp:
    def set_restricted_permissions(self, path):
        """Đặt quyền hạn chế cho thư mục"""
        try:
            # Đối với Windows
            if os.name == 'nt':
                # Chỉ cho phép quyền đọc và thực thi cho người dùng hiện tại
                os.chmod(path, stat.S_IREAD | stat.S_IEXEC)
            # Đối với Unix/Linux
            else:
                # Chỉ cho phép quyền đọc và thực thi cho chủ sở hữu
                os.chmod(path, stat.S_IRUSR | stat.S_IXUSR)
        except Exception as e:
            print(f"Không thể đặt quyền hạn chế: {str(e)}")
    
    def __init__(self, root):
        self.root = root
        self.root.title("Packer Detector")
        self.root.geometry("900x650")
        self.root.minsize(800, 600)
        
        # Thêm icon cho cửa sổ ứng dụng
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "icon.ico")
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)
        
        # Đường dẫn đến yara64.exe
        self.yara_path = "E:\\NT230\\coursework\\yara-v4.5.2-2326-win64\\yara64.exe"
        self.rule_path = ""
        self.target_path = ""
        self.is_recursive = tk.BooleanVar(value=False)
        
        # Thêm biến cho thư mục cách ly và log
        self.quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
        self.log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detection_log.json")
        
        # Tạo thư mục cách ly nếu chưa tồn tại
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)
            # Đặt quyền hạn chế cho thư mục
            self.set_restricted_permissions(self.quarantine_dir)
        
        # Tạo file log nếu chưa tồn tại
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump([], f)
        
        # Tạo style
        self.style = ttk.Style("darkly")
        
        # Tạo giao diện
        self.create_widgets()
        
        # Kiểm tra yara64.exe
        self.check_yara_executable()
    
    def check_yara_executable(self):
        if not os.path.exists(self.yara_path):
            messagebox.showwarning(
                "Cảnh báo", 
                f"Không tìm thấy yara64.exe tại {self.yara_path}\n"
                "Vui lòng chọn đường dẫn đến yara64.exe khi quét."
            )
    
    def create_widgets(self):
        # Tạo main frame
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill="both", expand=True)
        
        # Header với logo và tiêu đề
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill="x", pady=(0, 10))
        
        # Tiêu đề ứng dụng
        title_label = ttk.Label(
            header_frame, 
            text="PACKER DETECTOR", 
            font=("Segoe UI", 20, "bold"),
        )
        title_label.pack(side="top", pady=10)
        
        subtitle_label = ttk.Label(
            header_frame, 
            text="Phát hiện packer trong tệp thực thi sử dụng YARA", 
            font=("Segoe UI", 10)
        )
        subtitle_label.pack(side="top")
        
        # Frame cho các tùy chọn
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill="x", pady=10)
        
        # Frame cho YARA rule
        rule_frame = ttk.LabelFrame(options_frame, text="Tệp luật YARA", padding=10)
        rule_frame.pack(fill="x", pady=5)
        
        rule_inner_frame = ttk.Frame(rule_frame)
        rule_inner_frame.pack(fill="x")
        
        self.rule_label = ttk.Label(
            rule_inner_frame, 
            text="Chưa chọn tệp luật", 
            font=("Segoe UI", 9),
            bootstyle="secondary"
        )
        self.rule_label.pack(side="left", fill="x", expand=True)
        
        rule_button = ttk.Button(
            rule_inner_frame, 
            text="Chọn tệp luật", 
            command=self.select_rule,
            bootstyle="outline"
        )
        rule_button.pack(side="right", padx=5)
        
        # Frame cho target selection
        target_frame = ttk.LabelFrame(options_frame, text="Tệp/Thư mục để quét", padding=10)
        target_frame.pack(fill="x", pady=5)
        
        target_inner_frame = ttk.Frame(target_frame)
        target_inner_frame.pack(fill="x")
        
        self.target_label = ttk.Label(
            target_inner_frame, 
            text="Chưa chọn tệp/thư mục", 
            font=("Segoe UI", 9),
            bootstyle="secondary"
        )
        self.target_label.pack(side="left", fill="x", expand=True)
        
        target_file_button = ttk.Button(
            target_inner_frame, 
            text="Chọn tệp", 
            command=self.select_file,
            bootstyle="outline"
        )
        target_file_button.pack(side="right", padx=5)
        
        target_dir_button = ttk.Button(
            target_inner_frame, 
            text="Chọn thư mục", 
            command=self.select_directory,
            bootstyle="outline"
        )
        target_dir_button.pack(side="right", padx=5)
        
        # Recursive checkbox
        recursive_check = ttk.Checkbutton(
            target_inner_frame, 
            text="Quét đệ quy", 
            variable=self.is_recursive,
            bootstyle="round-toggle"
        )
        recursive_check.pack(side="right", padx=10)
        
        # Scan button
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=10)
        
        scan_button = ttk.Button(
            button_frame, 
            text="BẮT ĐẦU QUÉT", 
            command=self.start_scan,
            bootstyle="success",
            width=20
        )
        scan_button.pack(pady=5)
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Kết quả quét", padding=10)
        results_frame.pack(fill="both", expand=True, pady=5)
        
        # Create a scrolled text widget for results
        self.results_text = ScrolledText(results_frame, autohide=True, height=15)
        self.results_text.pack(fill="both", expand=True)
        
        # Configure text tags for colored output
        self.setup_text_tags()
        
        # Status bar
        self.status_var = tk.StringVar(value="Sẵn sàng")
        status_bar = ttk.Label(
            self.root, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN, 
            anchor=tk.W,
            padding=5
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Footer
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill="x", pady=5)
        
        footer_label = ttk.Label(
            footer_frame, 
            text="© 2023 Packer Detector - Powered by YARA", 
            font=("Segoe UI", 8),
            bootstyle="secondary"
        )
        footer_label.pack(side="left")
        
        view_log_button = ttk.Button(
            footer_frame, 
            text="Xem Log", 
            command=self.show_log,
            bootstyle="info",
            width=10
        )
        view_log_button.pack(side="right", padx=5)
        
        help_button = ttk.Button(
            footer_frame, 
            text="Trợ giúp", 
            command=self.show_help,
            bootstyle="link",
            width=10
        )
        help_button.pack(side="right")
    
    def setup_text_tags(self):
        """Thiết lập các tag màu sắc cho text widget"""
        # Tag cho tiêu đề (màu đỏ, đậm)
        self.results_text.tag_configure("title", foreground="#FF4444", font=("Segoe UI", 10, "bold"))
        
        # Tag cho thông tin quan trọng (màu cam)
        self.results_text.tag_configure("important", foreground="#FF8800", font=("Segoe UI", 9, "bold"))
        
        # Tag cho hash (màu xanh lá)
        self.results_text.tag_configure("hash", foreground="#44AA44", font=("Consolas", 8))
        
        # Tag cho rule (màu tím)
        self.results_text.tag_configure("rule", foreground="#8844FF", font=("Segoe UI", 9))
        
        # Tag cho hành động (màu xanh dương)
        self.results_text.tag_configure("action", foreground="#4488FF", font=("Segoe UI", 9, "italic"))
        
        # Tag cho đường phân cách
        self.results_text.tag_configure("separator", foreground="#666666")
        
        # Tag cho thông báo không tìm thấy (màu xám)
        self.results_text.tag_configure("no_result", foreground="#AAAAAA", font=("Segoe UI", 10, "italic"))
        
        # Tag cho lỗi (màu đỏ đậm)
        self.results_text.tag_configure("error", foreground="#CC0000", font=("Segoe UI", 9, "bold"))
    
    def select_rule(self):
        file_path = filedialog.askopenfilename(
            title="Chọn tệp luật YARA",
            filetypes=[("YARA Rules", "*.yar"), ("All Files", "*.*")]
        )
        if file_path:
            self.rule_path = file_path
            self.rule_label.config(text=os.path.basename(file_path))
    
    def select_file(self):
        file_path = filedialog.askopenfilename(
            title="Chọn tệp để quét",
            filetypes=[("Executable Files", "*.exe *.dll"), ("All Files", "*.*")]
        )
        if file_path:
            self.target_path = file_path
            self.target_label.config(text=os.path.basename(file_path))
    
    def select_directory(self):
        dir_path = filedialog.askdirectory(title="Chọn thư mục để quét")
        if dir_path:
            self.target_path = dir_path
            self.target_label.config(text=dir_path)
    
    def start_scan(self):
        if not self.rule_path:
            messagebox.showerror("Lỗi", "Vui lòng chọn tệp luật YARA!")
            return
        
        if not self.target_path:
            messagebox.showerror("Lỗi", "Vui lòng chọn tệp hoặc thư mục để quét!")
            return
        
        if not os.path.exists(self.yara_path):
            # Cho phép người dùng chọn yara64.exe
            yara_path = filedialog.askopenfilename(
                title="Chọn yara64.exe",
                filetypes=[("Executable Files", "*.exe"), ("All Files", "*.*")]
            )
            if yara_path:
                self.yara_path = yara_path
            else:
                return
        
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Đang quét...")
        
        # Start scanning in a separate thread to avoid freezing the UI
        threading.Thread(target=self.run_scan, daemon=True).start()
    
    def run_scan(self):
        try:
            # Build command
            cmd = [self.yara_path, "-f"]
            
            # Add recursive flag if needed and target is a directory
            if self.is_recursive.get() and os.path.isdir(self.target_path):
                cmd.append("-r")
            
            # Add rule file and target
            cmd.extend([self.rule_path, self.target_path])
            
            # Run the command
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8')
            stdout, stderr = process.communicate()
            
            if process.returncode != 0 and stderr:
                self.root.after(0, lambda: self.update_results(f"Lỗi: {stderr}"))
                return
            
            # Process and display results
            if stdout.strip():
                self.root.after(0, lambda: self.format_results(stdout))
            else:
                self.root.after(0, lambda: self.update_results("Không tìm thấy kết quả khớp."))
        
        except Exception as e:
            self.root.after(0, lambda: self.update_results(f"Lỗi: {str(e)}"))
        
        finally:
            self.root.after(0, lambda: self.status_var.set("Đã hoàn thành quét"))
    
    def calculate_file_hash(self, file_path):
        """Tính toán hash SHA256 của file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                # Đọc và cập nhật hash theo từng khối để tránh tải toàn bộ file vào bộ nhớ
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return f"Lỗi: {str(e)}"

    def quarantine_file(self, file_path):
        """Di chuyển file vào thư mục cách ly và đổi tên"""
        try:
            if not os.path.isfile(file_path):
                return None
                
            # Tạo tên file mới trong thư mục cách ly
            file_name = os.path.basename(file_path)
            base_name, ext = os.path.splitext(file_name)
            quarantine_name = f"{base_name}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.quar"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_name)
            
            # Di chuyển file
            shutil.move(file_path, quarantine_path)
            
            # Đặt quyền chỉ đọc cho file trong thư mục cách ly
            try:
                os.chmod(quarantine_path, stat.S_IREAD)
            except Exception:
                pass  # Bỏ qua lỗi permission trên Windows
            
            return quarantine_path
        except Exception as e:
            print(f"Không thể cách ly file: {str(e)}")
            return None

    def log_detection(self, file_path, file_hash, rules, quarantine_path):
        """Ghi log phát hiện vào file JSON"""
        try:
            # Đọc log hiện tại
            current_log = []
            if os.path.exists(self.log_file) and os.path.getsize(self.log_file) > 0:
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    try:
                        current_log = json.load(f)
                    except json.JSONDecodeError:
                        current_log = []
            
            # Tạo bản ghi mới
            log_entry = {
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "file_path": file_path,
                "file_name": os.path.basename(file_path),
                "sha256": file_hash,
                "rules": rules,
                "quarantine_path": quarantine_path
            }
            
            # Thêm vào log
            current_log.append(log_entry)
            
            # Ghi lại vào file
            with open(self.log_file, 'w', encoding='utf-8') as f:
                json.dump(current_log, f, indent=4, ensure_ascii=False)
                
        except Exception as e:
            print(f"Không thể ghi log: {str(e)}")
    
    def format_results(self, output):
        # Process the YARA output to a more readable format
        matches = {}
        detected_files = []
        
        lines = output.splitlines()
        
        # Parse YARA output format: rule_name file_path
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Tách rule và file path
            parts = line.split(' ', 1)
            if len(parts) >= 2:
                rule_name = parts[0]
                file_path = parts[1]
                
                if file_path not in matches:
                    matches[file_path] = []
                
                matches[file_path].append(rule_name)
                
                # Thêm file vào danh sách file đã phát hiện
                if file_path not in detected_files and os.path.isfile(file_path):
                    detected_files.append(file_path)
        
        # Clear and format the results with colors
        self.results_text.delete(1.0, tk.END)
        
        if not matches:
            self.results_text.insert(tk.END, "Không tìm thấy tệp nào được nén bởi packer.", "no_result")
            return
        
        # Format each detection result
        for i, (file_path, rules) in enumerate(matches.items()):
            if i > 0:
                self.results_text.insert(tk.END, "\n")
            
            # Tính toán hash của file
            file_hash = self.calculate_file_hash(file_path) if os.path.isfile(file_path) else "N/A"
            
            # Xác định loại packer từ các rule
            packer_types = {}
            for rule in rules:
                parts = rule.split('_')
                if len(parts) > 1:
                    packer_name = parts[1].capitalize()
                    if packer_name not in packer_types:
                        packer_types[packer_name] = 0
                    packer_types[packer_name] += 1
            
            # Hiển thị thông tin file với màu sắc
            self.results_text.insert(tk.END, "🔴 TỆP PHÁT HIỆN: ", "title")
            self.results_text.insert(tk.END, f"{file_path}\n")
            
            self.results_text.insert(tk.END, "🔹 Hash SHA256: ", "important")
            self.results_text.insert(tk.END, f"{file_hash}\n", "hash")
            
            # Hiển thị tóm tắt
            self.results_text.insert(tk.END, "🔹 Kết quả phát hiện: ", "important")
            self.results_text.insert(tk.END, f"Khớp với {len(rules)} rule YARA\n")
            
            # Hiển thị loại packer
            packer_summary = ", ".join([f"{name} ({count})" for name, count in packer_types.items()])
            self.results_text.insert(tk.END, "🔹 Loại Packer: ", "important")
            self.results_text.insert(tk.END, f"{packer_summary}\n")
            
            # Hiển thị chi tiết các rule
            self.results_text.insert(tk.END, "🔹 Chi tiết rule:\n", "important")
            for rule in rules:
                self.results_text.insert(tk.END, f"  ✓ {rule}\n", "rule")
            
            # Thêm thông tin về hành động đã thực hiện
            if os.path.isfile(file_path):
                quarantine_path = self.quarantine_file(file_path)
                if quarantine_path:
                    self.results_text.insert(tk.END, "🔹 Hành động: ", "important")
                    self.results_text.insert(tk.END, f"File đã được di chuyển đến thư mục cách ly\n", "action")
                    self.results_text.insert(tk.END, f"   📁 {quarantine_path}\n", "action")
                    
                    # Ghi log
                    self.log_detection(file_path, file_hash, rules, quarantine_path)
                else:
                    self.results_text.insert(tk.END, "🔹 Hành động: ", "important")
                    self.results_text.insert(tk.END, "Không thể cách ly file\n", "error")
            
            # Đường phân cách
            self.results_text.insert(tk.END, "=" * 60 + "\n", "separator")
    
    def update_results(self, text):
        if isinstance(text, str):
            # Nếu là string thông thường, hiển thị với tag phù hợp
            self.results_text.delete(1.0, tk.END)
            if "Lỗi:" in text:
                self.results_text.insert(tk.END, text, "error")
            elif "Không tìm thấy" in text:
                self.results_text.insert(tk.END, text, "no_result")
            else:
                self.results_text.insert(tk.END, text)
        # Nếu không phải string, có nghĩa là format_results đã xử lý màu sắc rồi
    
    def show_log(self):
        """Hiển thị cửa sổ log"""
        log_window = tk.Toplevel(self.root)
        log_window.title("Log phát hiện")
        log_window.geometry("800x600")
        log_window.minsize(600, 400)
        
        # Tạo frame chứa nội dung
        log_frame = ttk.Frame(log_window, padding=10)
        log_frame.pack(fill="both", expand=True)
        
        # Tiêu đề
        title_label = ttk.Label(
            log_frame, 
            text="Lịch sử phát hiện Packer", 
            font=("Segoe UI", 16, "bold")
        )
        title_label.pack(pady=10)
        
        # Tạo widget hiển thị log
        log_text = ScrolledText(log_frame, autohide=True)
        log_text.pack(fill="both", expand=True, pady=10)
        
        # Đọc và hiển thị log
        try:
            if os.path.exists(self.log_file) and os.path.getsize(self.log_file) > 0:
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    log_data = json.load(f)
                    
                if log_data:
                    log_content = []
                    for entry in log_data:
                        log_content.append(f"Thời gian: {entry['timestamp']}")
                        log_content.append(f"File: {entry['file_name']}")
                        log_content.append(f"Đường dẫn: {entry['file_path']}")
                        log_content.append(f"SHA256: {entry['sha256']}")
                        log_content.append(f"Các rule: {', '.join(entry['rules'])}")
                        log_content.append(f"Vị trí cách ly: {entry['quarantine_path']}")
                        log_content.append("-" * 60)
                    
                    log_text.insert(tk.END, "\n".join(log_content))
                else:
                    log_text.insert(tk.END, "Chưa có log nào được ghi lại.")
            else:
                log_text.insert(tk.END, "Chưa có log nào được ghi lại.")
        except Exception as e:
            log_text.insert(tk.END, f"Lỗi khi đọc log: {str(e)}")
        
        # Nút đóng và xóa log
        button_frame = ttk.Frame(log_frame)
        button_frame.pack(fill="x", pady=10)
        
        clear_log_button = ttk.Button(
            button_frame, 
            text="Xóa Log", 
            command=self.clear_log,
            bootstyle="danger",
            width=15
        )
        clear_log_button.pack(side="left", padx=5)
        
        close_button = ttk.Button(
            button_frame, 
            text="Đóng", 
            command=log_window.destroy,
            bootstyle="secondary",
            width=15
        )
        close_button.pack(side="right", padx=5)
    
    def clear_log(self):
        """Xóa toàn bộ log"""
        if messagebox.askyesno("Xác nhận", "Bạn có chắc chắn muốn xóa toàn bộ log?"):
            try:
                with open(self.log_file, 'w', encoding='utf-8') as f:
                    json.dump([], f)
                messagebox.showinfo("Thành công", "Đã xóa toàn bộ log.")
            except Exception as e:
                messagebox.showerror("Lỗi", f"Không thể xóa log: {str(e)}")
    
    def show_help(self):
        """Hiển thị cửa sổ trợ giúp"""
        help_window = tk.Toplevel(self.root)
        help_window.title("Trợ giúp Packer Detector")
        help_window.geometry("700x500")
        help_window.minsize(600, 400)
        
        # Tạo frame chứa nội dung
        help_frame = ttk.Frame(help_window, padding=10)
        help_frame.pack(fill="both", expand=True)
        
        # Tiêu đề
        title_label = ttk.Label(
            help_frame, 
            text="Hướng dẫn sử dụng Packer Detector", 
            font=("Segoe UI", 16, "bold")
        )
        title_label.pack(pady=10)
        
        # Tạo widget hiển thị hướng dẫn
        help_text = ScrolledText(help_frame, autohide=True)
        help_text.pack(fill="both", expand=True, pady=10)
        
        # Nội dung hướng dẫn
        help_content = """
# Hướng dẫn sử dụng Packer Detector

## 1. Chọn tệp luật YARA
- Nhấp vào nút "Chọn tệp luật" để chọn file luật YARA (*.yar)
- Các luật YARA phải có định dạng phù hợp để phát hiện packer

## 2. Chọn tệp hoặc thư mục để quét
- Nhấp vào nút "Chọn tệp" để quét một tệp thực thi
- Nhấp vào nút "Chọn thư mục" để quét một thư mục
- Đánh dấu "Quét đệ quy" nếu muốn quét cả các thư mục con

## 3. Bắt đầu quét
- Nhấp vào nút "BẮT ĐẦU QUÉT" để bắt đầu quá trình quét
- Kết quả sẽ hiển thị trong khu vực "Kết quả quét"

## 4. Xem log
- Nhấp vào nút "Xem Log" để xem lịch sử các file đã phát hiện

## 5. Tính năng cách ly
- Các file được phát hiện sẽ tự động được sao chép vào thư mục cách ly
- File gốc sẽ được giữ nguyên, chỉ tạo bản sao trong thư mục cách ly
- Thông tin hash SHA256 của file sẽ được lưu lại trong log

## Lưu ý
- Ứng dụng cần YARA engine để hoạt động
- File log sẽ lưu lại tất cả thông tin phát hiện
- Thư mục cách ly sẽ được tạo tự động trong thư mục chứa ứng dụng
        """
        
        help_text.insert(tk.END, help_content)
        
        # Nút đóng
        close_button = ttk.Button(
            help_frame, 
            text="Đóng", 
            command=help_window.destroy,
            bootstyle="secondary",
            width=15
        )
        close_button.pack(pady=10)

if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = PackerDetectorApp(root)
    root.mainloop()