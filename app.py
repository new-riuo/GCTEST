from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
import os
from extensions import db, login_manager
from models import User, Order, SKU, Process, Parameter, ProductImage, process_sequence, SystemParameter
from flask_login import login_user, logout_user, login_required, current_user

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///production_management.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 登录页面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            session['username'] = user.username
            session['role'] = user.role
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误', 'danger')
    return render_template('login.html')

# 退出登录
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

# 首页
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# 新增 home 路由
@app.route('/home')
@login_required
def home():
    return render_template('home.html')

# 管理后台 - 用户管理
@app.route('/admin/users')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        abort(403)
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
def admin_add_user():
    if current_user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('用户名已存在，请选择其他用户名', 'danger')
            return redirect(url_for('admin_add_user'))

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('用户添加成功', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('admin/add_user.html')

def has_permission(permission):
    return current_user.permissions and permission in current_user.permissions

#添加系统参数设置路由。
@app.route('/system_parameter_settings', methods=['GET', 'POST'])
@login_required
def system_parameter_settings():
    if current_user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        # 处理参数设置逻辑
        pass
    parameters = SystemParameter.query.all()
    return render_template('system_parameter_settings.html', parameters=parameters)

#添加权限验证逻辑
@app.route('/sensitive_operation', methods=['GET', 'POST'])
@login_required
def sensitive_operation():
    if not has_permission('sensitive_operation'):
        abort(403)
    # 处理敏感操作
    return render_template('sensitive_operation.html')

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    if current_user.role != 'admin':
        abort(403)
    
    user = User.query.get(user_id)
    if not user:
        flash('用户不存在', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != user_id:
            flash('用户名已存在，请选择其他用户名', 'danger')
            return redirect(url_for('admin_edit_user', user_id=user_id))

        user.username = username
        if password:
            user.set_password(password)
        user.role = role

        db.session.commit()
        flash('用户信息更新成功', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin/edit_user.html', user=user)

# 工序扫描页面
@app.route('/process_scan', methods=['GET', 'POST'])
@login_required
def process_scan():
    if request.method == 'POST':
        order_number = request.form.get('order_number')
        sku_code = request.form.get('sku_code')
        order = Order.query.filter_by(order_number=order_number).first()
        if order and order.sku.sku_code == sku_code:
            return redirect(url_for('process_select', order_id=order.id))
        else:
            flash('订单号或 SKU 码错误', 'danger')
    return render_template('process_scan.html')

# 工序选择页面
@app.route('/process_select/<int:order_id>', methods=['GET', 'POST'])
@login_required
def process_select(order_id):
    order = Order.query.get(order_id)
    processes = Process.query.all()
    if request.method == 'POST':
        process_id = request.form.get('process_id')
        quantity = int(request.form.get('quantity'))
        process_type = request.form.get('process_type')
        remarks = request.form.get('remarks')

        process = Process.query.get(process_id)
        for param in process.parameters:
            actual_value = request.form.get(f'param_{param.id}')
            if param.is_key and actual_value != param.value:
                flash('关键参数不合格', 'danger')
                return redirect(url_for('process_select', order_id=order_id))

        # 处理工序选择逻辑
        # 更新订单状态
        if process_type == 'rework':
            order.status = 'rework'
        elif process_type == 'normal':
            # 假设所有工序完成后更新状态
            # 这里需要根据实际逻辑判断
            order.status = 'processing'
        db.session.commit()

        return redirect(url_for('process_guide', order_id=order_id, process_id=process_id))
    return render_template('process_select.html', order=order, processes=processes)

# 工艺指导页面
@app.route('/process_guide/<int:order_id>/<int:process_id>')
@login_required
def process_guide(order_id, process_id):
    order = Order.query.get(order_id)
    process = Process.query.get(process_id)
    parameters = process.parameters
    return render_template('process_guide.html', order=order, process=process, parameters=parameters)

# 密码重置页面
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form.get('username')
        new_password = request.form.get('new_password')
        user = User.query.filter_by(username=username).first()
        if user:
            user.set_password(new_password)
            db.session.commit()
            flash('密码重置成功，请使用新密码登录', 'success')
            return redirect(url_for('login'))
        else:
            flash('用户名不存在', 'danger')
    return render_template('reset_password.html')

# 注册页面
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('用户名已存在，请选择其他用户名', 'danger')
            return redirect(url_for('login'))

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    return render_template('login.html')

#添加订单详情路由
@app.route('/order_detail/<int:order_id>')
@login_required
def order_detail(order_id):
    order = Order.query.get(order_id)
    return render_template('order_detail.html', order=order)

#订单状态变更
@app.route('/order_status_change/<int:order_id>', methods=['GET', 'POST'])
@login_required
def order_status_change(order_id):
    if current_user.role != 'admin':
        abort(403)
    order = Order.query.get(order_id)
    if request.method == 'POST':
        new_status = request.form.get('status')
        order.status = new_status
        db.session.commit()
        flash('订单状态更新成功', 'success')
        return redirect(url_for('order_detail', order_id=order_id))
    return render_template('order_status_change.html', order=order)
#生产报表路由
@app.route('/production_report', methods=['GET'])
@login_required
def production_report():
    if current_user.role != 'admin':
        abort(403)
    # 统计生产数量和生产进度
    # 这里需要根据实际情况编写统计逻辑
    production_quantity = 200
    production_progress = '80%'
    return render_template('production_report.html', production_quantity=production_quantity, production_progress=production_progress)

# 工艺管理 - 工艺流程列表
@app.route('/process_management', methods=['GET'])
@login_required
def process_management():
    if current_user.role != 'admin':
        abort(403)
    page = request.args.get('page', 1, type=int)
    per_page = 10
    processes = Process.query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('process_management.html', processes=processes)

# 工艺管理 - 编辑工艺流程
@app.route('/process_management/edit/<int:process_id>', methods=['GET', 'POST'])
@login_required
def edit_process(process_id):
    if current_user.role != 'admin':
        abort(403)
    process = Process.query.get(process_id)
    if not process:
        flash('工艺流程不存在', 'danger')
        return redirect(url_for('process_management'))
    if request.method == 'POST':
        process.name = request.form.get('name')
        process.process_code = request.form.get('process_code')
        process.sequence = int(request.form.get('sequence'))
        process.description = request.form.get('description')
        db.session.commit()
        flash('工艺流程更新成功', 'success')
        return redirect(url_for('process_management'))
    return render_template('edit_process.html', process=process)

# 产品管理 - 产品列表
@app.route('/product_management', methods=['GET'])
@login_required
def product_management():
    if current_user.role != 'admin':
        abort(403)
    page = request.args.get('page', 1, type=int)
    per_page = 10
    search_query = request.args.get('search')
    if search_query:
        skus = SKU.query.filter(SKU.name.contains(search_query)).paginate(page=page, per_page=per_page, error_out=False)
    else:
        skus = SKU.query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('product_management.html', skus=skus)

# 产品管理 - 添加产品
@app.route('/product_management/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if current_user.role != 'admin':
        abort(403)
    if request.method == 'POST':
        sku_code = request.form.get('sku_code')
        name = request.form.get('name')
        category = request.form.get('category')
        color = request.form.get('color')
        curvature = request.form.get('curvature')
        size = request.form.get('size')
        size_unit = request.form.get('size_unit')
        density = request.form.get('density')
        lace_type = request.form.get('lace_type')
        tail_type = request.form.get('tail_type')
        special_attribute = request.form.get('special_attribute')

        existing_sku = SKU.query.filter_by(sku_code=sku_code).first()
        if existing_sku:
            flash('SKU 码已存在，请选择其他 SKU 码', 'danger')
            return redirect(url_for('add_product'))

        new_sku = 库存保有单位(
            sku_code=sku_code,
            name=名称,
            category=类别,
            颜色=颜色,
            曲率=曲率
            大小=大小
            size_unit=size_unit,
            密度=密度,
            lace_type=蕾丝类型,
            尾部类型=尾部类型
            特殊属性=特殊属性
        输入：        输入：)
        db.会话.添加(新商品编号)
        db.会话.提交()
        flash('产品添加成功', '成功')
        返回 重定向(url_for('product_management'))
    返回 渲染模板('add_product.html')

# 产品管理 - 编辑产品
@app.路由('/product_management/edit/')
@登录所需
定义 编辑产品(商品库存单位ID):
    如果 current_user.role 不等于 'admin':
        中止(403)
    sku = SKU.查询.获取(商品库存编号)
    如果没有sku:
        闪光('产品不存在', '危险')
        返回 redirect重定向(url_for('product_management')
    如果请求。方法 == 'POST':
        sku.sku_code = request.form.get('sku_code')
()
        sku.类别 = 请求。表单.获取('类别')
        sku.颜色 = 请求.表单.获取('颜色')
        sku.曲率 = request.form.get('曲率')
        sku.大小 = request.表单.获取('大小')
        sku.尺寸单位 = 请求.表单.获取('尺寸单位')
        sku.密度 = 请求.表单.获取('密度')
        sku. lace_type  = request. form . get ('lace_type')
        sku.尾类型 = request.表单.获取('尾类型')
        sku 特殊属性 = request.表单.获取('特殊属性')

        db.会话.提交()
        flash('产品信息更新成功', '成功')
        返回 重定向(url_for('product_management'))
    返回 渲染模板('edit_product.html', sku=sku)

如果 __name__ == '__main__':
    使用应用。应用上下文():
        db.创建所有()
    # 开发环境使用 Flask 自带服务器
    app.运行(调试=真)
    admin = User.查询.按(角色='管理员').第一个()
    如果不是管理员：
        admin = 用户(用户名='admin', 角色='管理员')
        admin.设置密码('默认密码')  # 注意：默认密码需修改
        db.会话.添加(管理员)
        db.会话.提交()
否则:
    # 生产环境使用 Waitress
    从服务员导入 serve
    (应用程序, 主机=
