from PIL import Image, ImageDraw, ImageFont
import os

# Tạo hình ảnh
img = Image.new('RGBA', (256, 256), color=(0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Vẽ hình tròn nền
draw.ellipse((20, 20, 236, 236), fill=(52, 152, 219))

# Vẽ biểu tượng khóa
draw.rectangle((90, 100, 166, 180), fill=(255, 255, 255))
draw.rectangle((100, 70, 156, 100), fill=(255, 255, 255))

# Vẽ biểu tượng quét
draw.line((70, 130, 186, 130), fill=(52, 152, 219), width=10)
draw.line((70, 150, 186, 150), fill=(52, 152, 219), width=10)
draw.line((70, 170, 186, 170), fill=(52, 152, 219), width=10)

# Lưu file icon
icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.ico')
img.save(icon_path, format='ICO')

print(f"Đã tạo file icon tại: {icon_path}")