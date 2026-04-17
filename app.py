import os
from flask import Flask, request, jsonify, render_template
from PIL import Image
from sd_parsers import ParserManager
import io

app = Flask(__name__)

# 设置上传文件夹（可选，用于调试）
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 限制 16MB

@app.route('/')
def index():
    """返回前端页面"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_image():
    """接收图片，读取数据，返回处理结果"""
    # 1. 检查是否有文件被上传
    if 'image' not in request.files:
        return jsonify({'error': '没有上传文件'}), 400

    file = request.files['image']

    if file.filename == '':
        return jsonify({'error': '文件名为空'}), 400

    # 2. 读取图片数据（内存中操作，无需保存到磁盘）
    try:
        img_bytes = file.read()                     # 读取二进制数据
        img = Image.open(io.BytesIO(img_bytes))     # 用 PIL 打开

        # 3. 尝试解析 Stable Diffusion 参数（如果图片包含元数据）
        parser_manager = ParserManager()
        prompt_info = parser_manager.parse(img)   # ✅ 传入字节数据，不是字符串

        # 安全提取 prompt 和 negative_prompt
        prompt = None
        negative_prompt = None
        if prompt_info is not None:
            # 根据 sd_parsers 的实际结构提取（常见结构）
            if hasattr(prompt_info, 'prompts') and prompt_info.prompts:
                prompt = prompt_info.prompts[0].value
            if hasattr(prompt_info, 'negative_prompts') and prompt_info.negative_prompts:
                negative_prompt = prompt_info.negative_prompts[0].value

        # 4. 提取图片基础信息
        width, height = img.size
        img_format = img.format
        file_size = len(img_bytes)                   # 字节数

        # 5. 返回结果
        result = {
            'success': True,
            'width': width,
            'height': height,
            'format': img_format,
            'file_size_bytes': file_size,
            'file_size_kb': round(file_size / 1024, 2),   # ✅ 加上了逗号
            'Prompt': prompt,                              # 键名保持大驼峰，值用变量 prompt
            'Negative Prompt': negative_prompt             # 键名含空格，值用变量 negative_prompt
        }
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'图片处理失败: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)