import cv2
import numpy as np
from PIL import Image, ImageTk, ImageOps, ImageEnhance
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
from collections import Counter
import random

class DigitalWatermarkSystem:
    # 系统常量
    SYNC_HEADER = "10101010"  # 8位同步头
    EMBED_POSITIONS = [(3,3), (4,4), (5,5)]  # 嵌入位置
    DEFAULT_ALPHA = 0.15  # 默认水印强度

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("数字水印系统 v2.0")
        self.alpha = tk.DoubleVar(value=self.DEFAULT_ALPHA)
        self.create_ui()
        self.setup_params()

    def setup_params(self):
        """初始化参数"""
        self.watermark_length = 0
        self.embedded_alpha = None

    def create_ui(self):
        """创建用户界面"""
        # 控制面板
        control_frame = tk.Frame(self.root, padx=10, pady=10)
        control_frame.pack(side=tk.LEFT, fill=tk.Y)

        # 图像显示区
        img_frame = tk.Frame(self.root)
        img_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)

        # 原始图像
        tk.Label(control_frame, text="原始图像:").grid(row=0, column=0, sticky='e')
        self.original_entry = tk.Entry(control_frame, width=40)
        self.original_entry.grid(row=0, column=1)
        tk.Button(control_frame, text="浏览", command=self.browse_original).grid(row=0, column=2)

        # 水印设置
        tk.Label(control_frame, text="水印文本:").grid(row=1, column=0, sticky='e')
        self.watermark_entry = tk.Entry(control_frame, width=40)
        self.watermark_entry.grid(row=1, column=1)

        # 水印强度
        tk.Label(control_frame, text="水印强度:").grid(row=2, column=0, sticky='e')
        tk.Scale(control_frame, from_=0.01, to=0.5, resolution=0.01, 
                orient=tk.HORIZONTAL, variable=self.alpha).grid(row=2, column=1)

        # 操作按钮
        tk.Button(control_frame, text="嵌入水印", command=self.embed_ui,
                 bg='#4CAF50', fg='white').grid(row=3, column=1, pady=5)
        tk.Button(control_frame, text="提取水印", command=self.extract_ui,
                 bg='#2196F3', fg='white').grid(row=4, column=1, pady=5)
        tk.Button(control_frame, text="鲁棒性测试", command=self.robustness_test_ui,
                 bg='#FF9800', fg='white').grid(row=5, column=1, pady=5)

        # 结果显示
        tk.Label(control_frame, text="提取结果:").grid(row=6, column=0, sticky='ne')
        self.result_text = tk.Text(control_frame, height=5, width=40)
        self.result_text.grid(row=6, column=1)

        # 图像显示
        self.original_img = tk.Label(img_frame)
        self.original_img.pack(side=tk.LEFT, padx=5)
        self.watermarked_img = tk.Label(img_frame)
        self.watermarked_img.pack(side=tk.LEFT, padx=5)

    # 核心算法 --------------------------------------------------
    
    def embed(self, img_path, watermark, output_path):
        """增强的水印嵌入算法"""
        alpha = self.alpha.get()
        
        try:
            # 1. 图像预处理
            img = cv2.imread(img_path)
            if img is None:
                raise ValueError("无法读取图像文件")
            
            # 2. 准备水印数据
            watermark_bin = self.SYNC_HEADER + ''.join(f"{ord(c):08b}" for c in watermark)
            self.watermark_length = len(watermark)
            
            # 3. DCT域嵌入
            yuv = cv2.cvtColor(img, cv2.COLOR_BGR2YUV)
            y, u, v = cv2.split(yuv)
            dct = cv2.dct(np.float32(y)/255.0)
            
            rows, cols = dct.shape
            pos = 0
            
            for i in range(0, rows, 8):
                for j in range(0, cols, 8):
                    if pos >= len(watermark_bin):
                        break
                    
                    # 多位置嵌入
                    bit = int(watermark_bin[pos])
                    for x, y in self.EMBED_POSITIONS:
                        if i+x < rows and j+y < cols:
                            neighborhood = dct[i+x-1:i+x+2, j+y-1:j+y+2]
                            avg = np.mean(neighborhood)
                            dct[i+x,j+y] = avg * (1 + alpha*bit) if bit else avg * (1 - alpha*0.5)
                    pos += 1
            
            # 4. 逆变换保存
            idct = cv2.idct(dct)*255.0
            y_watermarked = np.uint8(np.clip(idct, 0, 255))
            
            merged = cv2.merge((y_watermarked, u, v))
            watermarked = cv2.cvtColor(merged, cv2.COLOR_YUV2BGR)
            cv2.imwrite(output_path, watermarked)
            
            self.embedded_alpha = alpha
            return True
            
        except Exception as e:
            print(f"[ERROR] 嵌入失败: {str(e)}")
            return False

    def extract(self, watermarked_path, original_path):
        """增强的水印提取算法"""
        try:
            # 1. 读取图像
            original = cv2.imread(original_path)
            watermarked = cv2.imread(watermarked_path)
            
            if original is None or watermarked is None:
                raise ValueError("无法读取图像文件")
            
            # 2. 统一尺寸
            watermarked = cv2.resize(watermarked, (original.shape[1], original.shape[0]))
            
            # 3. DCT变换
            original_yuv = cv2.cvtColor(original, cv2.COLOR_BGR2YUV)
            watermarked_yuv = cv2.cvtColor(watermarked, cv2.COLOR_BGR2YUV)
            
            dct_original = cv2.dct(np.float32(original_yuv[:,:,0])/255.0)
            dct_watermarked = cv2.dct(np.float32(watermarked_yuv[:,:,0])/255.0)
            
            # 4. 提取水印
            extracted_bits = []
            sync_buffer = ""
            
            for i in range(0, dct_watermarked.shape[0], 8):
                for j in range(0, dct_watermarked.shape[1], 8):
                    # 多位置投票
                    votes = []
                    for x, y in self.EMBED_POSITIONS:
                        if i+x >= dct_watermarked.shape[0] or j+y >= dct_watermarked.shape[1]:
                            continue
                        
                        orig_val = dct_original[i+x,j+y]
                        wm_val = dct_watermarked[i+x,j+y]
                        threshold = orig_val * (self.embedded_alpha or self.alpha.get()) * 0.3
                        
                        if abs(wm_val - orig_val) > abs(threshold):
                            votes.append(1 if wm_val > orig_val else 0)
                    
                    if votes:
                        bit = int(np.mean(votes) > 0.5)
                        extracted_bits.append(str(bit))
                        
                        # 同步头检测
                        if len(sync_buffer) < len(self.SYNC_HEADER):
                            sync_buffer += str(bit)
                        else:
                            sync_buffer = sync_buffer[1:] + str(bit)
                            
                            if sync_buffer == self.SYNC_HEADER:
                                extracted_bits = extracted_bits[-len(self.SYNC_HEADER):]
            
            # 5. 解码水印
            watermark_bits = ''.join(extracted_bits)
            sync_index = watermark_bits.find(self.SYNC_HEADER)
            
            if sync_index == -1:
                return "ERROR: 同步头未找到"
            
            watermark = ""
            bits = watermark_bits[sync_index+len(self.SYNC_HEADER):]
            
            for i in range(0, len(bits), 8):
                byte = bits[i:i+8]
                if len(byte) == 8:
                    try:
                        watermark += chr(int(byte, 2))
                    except:
                        watermark += "?"
            
            return watermark[:self.watermark_length] if self.watermark_length > 0 else watermark
            
        except Exception as e:
            print(f"[ERROR] 提取失败: {str(e)}")
            return f"ERROR: {str(e)}"

    # 用户界面操作 --------------------------------------------------

    def browse_original(self):
        """选择原始图像"""
        path = filedialog.askopenfilename(filetypes=[("图像文件", "*.jpg;*.jpeg;*.png;*.bmp")])
        if path:
            self.original_entry.delete(0, tk.END)
            self.original_entry.insert(0, path)
            self.show_image(path, self.original_img)

    def show_image(self, path, label_widget, size=(400, 400)):
        """显示图像"""
        try:
            img = Image.open(path)
            img.thumbnail(size)
            photo = ImageTk.PhotoImage(img)
            label_widget.config(image=photo)
            label_widget.image = photo
        except Exception as e:
            messagebox.showerror("错误", f"无法显示图像: {str(e)}")

    def embed_ui(self):
        """嵌入水印界面"""
        original_path = self.original_entry.get()
        watermark = self.watermark_entry.get()
        
        if not original_path or not watermark:
            messagebox.showwarning("警告", "请选择原始图像并输入水印文本")
            return
        
        output_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG文件", "*.png"), ("JPEG文件", "*.jpg")],
            title="保存含水印图像"
        )
        
        if output_path:
            if self.embed(original_path, watermark, output_path):
                self.show_image(output_path, self.watermarked_img)
                messagebox.showinfo("成功", "水印嵌入完成！")
            else:
                messagebox.showerror("错误", "水印嵌入失败，请检查控制台输出")

    def extract_ui(self):
        """提取水印界面"""
        watermarked_path = filedialog.askopenfilename(
            filetypes=[("图像文件", "*.jpg;*.jpeg;*.png;*.bmp")],
            title="选择含水印图像"
        )
        
        if not watermarked_path:
            return
            
        original_path = self.original_entry.get()
        if not original_path:
            messagebox.showwarning("警告", "请先选择原始图像路径")
            return
        
        # 询问水印长度
        if self.watermark_length <= 0:
            length = simpledialog.askinteger(
                "输入", "请输入水印文本长度(字符数):",
                parent=self.root, minvalue=1, maxvalue=100
            )
            if length:
                self.watermark_length = length
            else:
                return
        
        result = self.extract(watermarked_path, original_path)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, result)
        self.show_image(watermarked_path, self.watermarked_img)

    # 鲁棒性测试 --------------------------------------------------

    def robustness_test_ui(self):
        """鲁棒性测试界面"""
        original_path = self.original_entry.get()
        watermark = self.watermark_entry.get()
        
        if not original_path or not watermark:
            messagebox.showwarning("警告", "请先选择图像并设置水印")
            return
        
        test_dir = filedialog.askdirectory(title="选择测试结果保存目录")
        if not test_dir:
            return
        
        tester = RobustnessTester(self)
        results = tester.run_full_test(original_path, watermark, test_dir)
        
        # 显示测试结果
        result_window = tk.Toplevel(self.root)
        result_window.title("鲁棒性测试结果")
        
        text = tk.Text(result_window, width=80, height=20)
        text.pack(padx=10, pady=10)
        
        text.insert(tk.END, "=== 鲁棒性测试报告 ===\n\n")
        text.insert(tk.END, f"测试图像: {original_path}\n")
        text.insert(tk.END, f"水印文本: {watermark}\n")
        text.insert(tk.END, f"保存目录: {test_dir}\n\n")
        text.insert(tk.END, f"{'测试项':<20}{'状态':<10}{'提取结果':<20}\n")
        text.insert(tk.END, "-"*50 + "\n")
        
        success_count = 0
        for name, status, extracted in results:
            status_text = "通过" if status else "失败"
            color = "green" if status else "red"
            text.insert(tk.END, 
                       f"{name:<20}{status_text:<10}{extracted:<20}\n",
                       color)
            if status:
                success_count += 1
        
        text.insert(tk.END, "\n综合成功率: {:.1f}%\n".format(
            success_count/len(results)*100))
        
        text.tag_config("green", foreground="green")
        text.tag_config("red", foreground="red")

    def run(self):
        """运行主程序"""
        self.root.mainloop()


class RobustnessTester:
    """鲁棒性测试工具类"""
    def __init__(self, watermark_system):
        self.system = watermark_system
    
    def run_full_test(self, original_path, watermark, output_dir):
        """执行全套鲁棒性测试"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # 生成基准含水印图像
        base_path = os.path.join(output_dir, "base.png")
        self.system.embed(original_path, watermark, base_path)
        
        # 定义测试项
        tests = [
            ("旋转10度", self._rotate_10),
            ("旋转45度", self._rotate_45),
            ("水平翻转", self._flip_horizontal),
            ("垂直翻转", self._flip_vertical),
            ("裁剪10%", self._crop_10),
            ("缩放90%", self._scale_90),
            ("亮度+30%", self._brightness_30),
            ("对比度+50%", self._contrast_50),
            ("JPEG压缩85", self._jpeg_85),
            ("高斯噪声", self._gaussian_noise),
            ("平移20px", self._shift_20)
        ]
        
        # 执行测试
        results = []
        for name, func in tests:
            test_path = os.path.join(output_dir, f"test_{name}.png")
            func(base_path, test_path)
            extracted = self.system.extract(test_path, original_path)
            success = extracted == watermark
            results.append((name, success, extracted))
            
        return results

    # 测试方法实现
    def _rotate_10(self, input_path, output_path):
        img = Image.open(input_path)
        img = img.rotate(10, expand=True, fillcolor="white")
        img.save(output_path)

    def _rotate_45(self, input_path, output_path):
        img = Image.open(input_path)
        img = img.rotate(45, expand=True, fillcolor="white")
        img.save(output_path)

    def _flip_horizontal(self, input_path, output_path):
        img = Image.open(input_path)
        img = ImageOps.mirror(img)
        img.save(output_path)

    def _flip_vertical(self, input_path, output_path):
        img = Image.open(input_path)
        img = ImageOps.flip(img)
        img.save(output_path)

    def _crop_10(self, input_path, output_path):
        img = Image.open(input_path)
        w, h = img.size
        img = img.crop((int(w*0.1), int(h*0.1), int(w*0.9), int(h*0.9)))
        img.save(output_path)

    def _scale_90(self, input_path, output_path):
        img = Image.open(input_path)
        w, h = img.size
        img = img.resize((int(w*0.9), int(h*0.9)))
        img.save(output_path)

    def _brightness_30(self, input_path, output_path):
        img = Image.open(input_path)
        enhancer = ImageEnhance.Brightness(img)
        img = enhancer.enhance(1.3)
        img.save(output_path)

    def _contrast_50(self, input_path, output_path):
        img = Image.open(input_path)
        enhancer = ImageEnhance.Contrast(img)
        img = enhancer.enhance(1.5)
        img.save(output_path)

    def _jpeg_85(self, input_path, output_path):
        img = Image.open(input_path)
        img.save(output_path, quality=85)

    def _gaussian_noise(self, input_path, output_path):
        img = cv2.imread(input_path)
        mean = 0
        var = 10
        sigma = var ** 0.5
        gauss = np.random.normal(mean, sigma, img.shape)
        noisy = np.clip(img + gauss, 0, 255).astype(np.uint8)
        cv2.imwrite(output_path, noisy)

    def _shift_20(self, input_path, output_path):
        img = cv2.imread(input_path)
        rows, cols = img.shape[:2]
        M = np.float32([[1, 0, 20], [0, 1, 20]])
        shifted = cv2.warpAffine(img, M, (cols, rows))
        cv2.imwrite(output_path, shifted)


if __name__ == "__main__":
    # 检查依赖
    try:
        import cv2
        import numpy as np
        from PIL import Image, ImageTk, ImageOps, ImageEnhance
    except ImportError as e:
        print(f"缺少依赖库: {str(e)}")
        print("请执行: pip install opencv-python numpy pillow")
        exit(1)
    
    app = DigitalWatermarkSystem()
    app.run()