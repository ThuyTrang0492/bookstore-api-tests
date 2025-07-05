const jsonServer = require('json-server');
const server = jsonServer.create();
const router = jsonServer.router('db.json');
const middlewares = jsonServer.defaults();

server.use(middlewares);
server.use(jsonServer.bodyParser);

// ======== Đảm bảo ID nằm ở đầu mỗi object ========
server.use((req, res, next) => {
  const oldJson = res.json.bind(res);
  res.json = (data) => {
    const moveIdFirst = (obj) => {
      if (Array.isArray(obj)) return obj.map(moveIdFirst);
      if (obj && typeof obj === 'object' && 'id' in obj) {
        const { id, ...rest } = obj;
        return { id, ...rest };
      }
      return obj;
    };
    oldJson(moveIdFirst(data));
  };
  next();
});

// Middleware validate bookId/userId trên các route GET cụ thể
server.use((req, res, next) => {
  const url = req.originalUrl;
  const method = req.method;

  if (method === 'GET' && (url.startsWith('/books/') || url.startsWith('/users/'))) {
    const id = url.split('/')[2]?.split('?')[0];
    if (!id) {
      return res.status(404).json({ message: '❌ Thiếu ID trong URL (bookId hoặc userId).' });
    }
    if (!/^\d+$/.test(id)) {
      return res.status(400).json({ message: `❌ ID '${id}' không hợp lệ. Phải là số nguyên dương.` });
    }
  }

  next();
});

// ======== Phân quyền từ token ========
function getRoleFromToken(token) {
  if (token === 'Bearer fake-admin-token-999') return 'admin';
  if (token === 'Bearer fake-user-token-123') return 'user';
  return null;
}
function requireRole(requiredRole) {
  return (req, res, next) => {
    const role = getRoleFromToken(req.headers.authorization);
    if (role === requiredRole || (requiredRole === 'user' && role === 'admin')) return next();
    return res.status(403).json({ message: `Access denied. ${requiredRole} only.` });
  };
}

// ======== Đăng nhập ========
server.post('/login_user', (req, res) => {
  const { username, password } = req.body;
  const user = router.db.get('users').find({ username, password, role: 'user' }).value();
  if (user) return res.status(200).json({ access_token: 'fake-user-token-123', user: { id: user.id, username, role: user.role } });
  res.status(401).json({ message: 'User login failed' });
});
server.post('/login_admin', (req, res) => {
  const { username, password } = req.body;
  const admin = router.db.get('users').find({ username, password, role: 'admin' }).value();
  if (admin) return res.status(200).json({ access_token: 'fake-admin-token-999', user: { id: admin.id, username, role: admin.role } });
  res.status(401).json({ message: 'Admin login failed' });
});

// ======== GET /users với tìm kiếm gần đúng và validate ========
server.get('/users',requireRole('admin'),(req, res, next) => {
  const query = req.query;
  const db = router.db;
  let users = db.get('users').value();

  const allowedKeys = ['username', 'email', 'fullname', 'address', 'status', 'role'];
  const filterKeys = Object.keys(query).filter(k => !['_page', '_limit', '_sort', '_order'].includes(k));

  const invalidKeys = filterKeys.filter(k => !allowedKeys.includes(k));
  if (invalidKeys.length > 0) {
    return res.status(400).json({
      message: `❌ Trường không hợp lệ trong truy vấn: ${invalidKeys.join(', ')}.`,
      hint: `Chỉ được phép lọc theo: ${allowedKeys.join(', ')}`
    });
  }

  if (filterKeys.length === 0) return next();

  if ('password' in query) {
    return res.status(403).json({ message: '❌ Không được phép tìm kiếm theo password.' });
  }
  
  // Kiểm tra trường null, undefined, hoặc rỗng
for (const key of filterKeys) {
  const value = query[key];
  if (
    value == null ||                                      // null hoặc undefined
    (typeof value === 'string' && (
      value.trim() === '' ||                              // rỗng hoặc toàn khoảng trắng
      value.trim().toLowerCase() === 'null'               // chuỗi "null"
    ))
  ) {
    return res.status(400).json({ message: `❌ Trường '${key}' không được để trống.` });
  }
}

  for (const key of filterKeys) {
    if (key !== 'email' && typeof query[key] === 'string' && query[key].includes('@')) {
      return res.status(400).json({ message: `❌ Trường '${key}' không được chứa ký tự @ trong tìm kiếm.` });
    }
  }

  users = users.filter(user => {
    return filterKeys.every(key => {
      if (!(key in user)) return false;
      const val = String(user[key]).toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, '');
      const q = String(query[key]).toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, '');
      return val.includes(q);
    });
  });

  res.status(200).json(users);
});

// ======== Auto tăng ID ========
function addItemWithAutoId(res, resourceName, newItem) {
  const db = router.db;
  const items = db.get(resourceName).value();
  const numericIds = items.map(i => parseInt(i.id)).filter(id => !isNaN(id));
  const maxId = numericIds.length > 0 ? Math.max(...numericIds) : 0;
  newItem.id = (maxId + 1).toString();
  db.get(resourceName).push(Object.assign({ id: newItem.id }, newItem)).write();
  const reordered = { id: newItem.id, ...newItem };
  res.status(201).json(reordered);
}

// ======== POST /books (admin only) ========
server.post('/books', requireRole('admin'), (req, res) => {
  const { title, author, price, category, stock, rating, publishedYear, status } = req.body;
  const currentYear = new Date().getFullYear();

  const requiredFields = { title, author, price, category, stock, rating, publishedYear, status };
  for (const [key, value] of Object.entries(requiredFields)) {
    if (typeof value === 'string' && value.trim() === '') {
      return res.status(400).json({ message: `❌ Trường '${key}' không được chỉ chứa khoảng trắng.` });
    }
  }

  if (price < 0 || stock < 0)
    return res.status(400).json({ message: '❌ price và stock không được âm.' });

  if (rating < 1 || rating > 5)
    return res.status(400).json({ message: '❌ rating phải từ 1 đến 5.' });

  if (publishedYear < 0 || publishedYear > currentYear)
    return res.status(400).json({ message: `❌ Năm xuất bản phải nằm trong khoảng hợp lệ (0 → ${currentYear}).` });

  if (status && !['available', 'out_of_stock'].includes(status)) {
    return res.status(400).json({ message: '❌ Trường status chỉ được là "available" hoặc "out_of_stock".' });
  }

  addItemWithAutoId(res, 'books', req.body);
});

// ======== POST /reviews (bắt buộc đủ trường) ========
server.post('/reviews', (req, res) => {
  const db = router.db;
  const { bookId, userId, rating, comment, createdAt } = req.body;

  // 🛑 Kiểm tra các trường bắt buộc
  if (!bookId || !userId || typeof rating === 'undefined' || typeof comment === 'undefined') {
    return res.status(400).json({ message: '❌ Các trường bắt buộc: bookId, userId, rating, comment.' });
  }

  // 🔢 Kiểm tra định dạng dữ liệu
  if (!/^\d+$/.test(String(bookId))) {
    return res.status(400).json({ message: '❌ bookId phải là số nguyên dương.' });
  }
  if (!/^\d+$/.test(String(userId))) {
    return res.status(400).json({ message: '❌ userId phải là số nguyên dương.' });
  }
  if (typeof rating !== 'number' || rating < 1 || rating > 5) {
    return res.status(400).json({ message: '❌ rating phải là số từ 1 đến 5.' });
  }
  if (typeof comment !== 'string' || comment.trim() === '') {
    return res.status(400).json({ message: '❌ comment không được rỗng hoặc chỉ chứa khoảng trắng.' });
  }

  // 📅 Kiểm tra createdAt (nếu có)
  if (createdAt && isNaN(Date.parse(createdAt))) {
    return res.status(400).json({ message: '❌ createdAt phải đúng định dạng ISO (YYYY-MM-DDTHH:mm:ss.sssZ).' });
  }

  // 🔍 Kiểm tra tồn tại book và user
  const book = db.get('books').find({ id: String(bookId) }).value();
  const user = db.get('users').find({ id: String(userId) }).value();

  if (!book) return res.status(400).json({ message: `❌ Book ${bookId} không tồn tại.` });
  if (!user) return res.status(400).json({ message: `❌ User ${userId} không tồn tại.` });
  if (user.status !== 'active') return res.status(400).json({ message: `❌ Tài khoản '${user.username || user.fullname}' đang không hoạt động.` });

  // ✅ Tạo review nếu hợp lệ
  addItemWithAutoId(res, 'reviews', req.body);
});


server.post('/orders', (req, res) => {
  const db = router.db;
  const { userId, items, createdAt, shippingMethod } = req.body;

  // ✅ Hàm kiểm tra số nguyên dương
  function validatePositiveInteger(value, fieldName) {
    if (value === null) {
      return `${fieldName} không được null.`;
    }

    const strVal = String(value).trim();

    if (strVal === '') {
      return `${fieldName} không được rỗng.`;
    }

    if (/[^0-9]/.test(strVal)) {
      return `${fieldName} chứa ký tự không hợp lệ.`;
    }

    const num = Number(strVal);
    if (!Number.isInteger(num) || num <= 0) {
      return `${fieldName} phải là số nguyên dương.`;
    }

    return null; // ✅ Hợp lệ
  }

  // ✅ 1. Kiểm tra userId
  const userIdStr = String(userId);
  const userIdError = validatePositiveInteger(userIdStr, 'userId');
  if (userIdError) {
    return res.status(400).json({ message: `❌ ${userIdError}` });
  }

  // ✅ 2. Tìm user
  const user = db.get('users').find({ id: userIdStr }).value();
  if (!user) {
    return res.status(400).json({ message: `❌ Không tìm thấy user có id = ${userId}.` });
  }

  if (!user.status || user.status !== 'active') {
    return res.status(400).json({ message: `❌ Tài khoản '${user.username || user.fullname || 'không xác định'}' đang không hoạt động.` });
  }

  // ✅ 3. Kiểm tra items
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ message: '❌ Đơn hàng phải có ít nhất 1 sản phẩm (items).' });
  }

  for (const [i, item] of items.entries()) {
    const bookIdError = validatePositiveInteger(item.bookId, `bookId tại vị trí ${i}`);
    if (bookIdError) {
      return res.status(400).json({ message: `❌ ${bookIdError}` });
    }

    if (!item.quantity || typeof item.quantity !== 'number' || item.quantity <= 0) {
      return res.status(400).json({ message: `❌ quantity tại vị trí ${i} phải là số nguyên dương.` });
    }

    const bookIdStr = String(item.bookId);
    const book = db.get('books').find({ id: bookIdStr }).value();
    if (!book) {
      return res.status(400).json({ message: `❌ Book với id ${item.bookId} không tồn tại.` });
    }
  }

  // ✅ 4. Kiểm tra ngày tạo (nếu có)
  if (createdAt && isNaN(Date.parse(createdAt))) {
    return res.status(400).json({ message: '❌ createdAt phải đúng định dạng ISO (YYYY-MM-DDTHH:mm:ss.sssZ).' });
  }

  // ✅ 5. Kiểm tra shippingMethod
  const allowedShipping = ['standard', 'express'];
  if (!shippingMethod || typeof shippingMethod !== 'string' || !allowedShipping.includes(shippingMethod)) {
    return res.status(400).json({
      message: `❌ Trường 'shippingMethod' là bắt buộc và chỉ được là: ${allowedShipping.join(', ')}.`
    });
  }

  // ✅ 6. Tạo đơn hàng với role tự động từ user
const newOrder = {
  ...req.body,
  role: user.role || 'user' // mặc định là 'user' nếu không có role
};

addItemWithAutoId(res, 'orders', newOrder);

});

// ======== POST /users (admin only) ========
server.post('/users', requireRole('admin'), (req, res) => {
  const { username, password, role, fullname, email, address, status } = req.body;

  // 🛑 Kiểm tra các trường bắt buộc
  const requiredFields = { username, password, role, fullname, email, address, status };
  for (const [key, value] of Object.entries(requiredFields)) {
    if (typeof value === 'undefined') return res.status(400).json({ message: `❌ Trường '${key}' là bắt buộc.` });
    if (typeof value !== 'string') return res.status(400).json({ message: `❌ Trường '${key}' phải là chuỗi.` });
    if (value.trim() === '') return res.status(400).json({ message: `❌ Trường '${key}' không được chỉ chứa khoảng trắng.` });
  }

  // 🧪 Kiểm tra giá trị hợp lệ của role và status
  if (!['admin', 'user'].includes(role)) {
    return res.status(400).json({ message: '❌ role chỉ được là "admin" hoặc "user".' });
  }
  if (!['active', 'unactive'].includes(status)) {
    return res.status(400).json({ message: '❌ status chỉ được là "active" hoặc "unactive".' });
  }

  // 🔒 Kiểm tra username & password không chứa ký tự đặc biệt tiếng Việt
  const noVietnamese = /^[\x00-\x7F]+$/;
  if (!noVietnamese.test(username)) return res.status(400).json({ message: '❌ username không được chứa dấu tiếng Việt hoặc ký tự đặc biệt.' });
  if (!noVietnamese.test(password)) return res.status(400).json({ message: '❌ password không được chứa dấu tiếng Việt hoặc ký tự đặc biệt.' });

  // ✅ Kiểm tra độ mạnh của password
  if (password.length < 8) {
    return res.status(400).json({ message: '❌ Mật khẩu phải có ít nhất 8 ký tự.' });
  }
  const specialCharRegex = /[!@#$%^&*(),.?":{}|<>]/;
  if (!specialCharRegex.test(password)) {
    return res.status(400).json({ message: '❌ Mật khẩu phải chứa ít nhất 1 ký tự đặc biệt.' });
  }

  // 📧 Kiểm tra định dạng email
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email) || !email.includes('.com')) {
    return res.status(400).json({ message: '❌ Email không hợp lệ. Email phải đúng định dạng và chứa ".com"' });
  }
  // ❌ Không cho phép trùng username
  const isUsernameExist = router.db.get('users').find({ username }).value();
  if (isUsernameExist) {
    return res.status(409).json({ message: `❌ Username '${username}' đã tồn tại. Vui lòng chọn username khác.` });
  }

  // ✅ Nếu hợp lệ thì tạo user
  addItemWithAutoId(res, 'users', req.body);
});


// ======== Middleware kiểm tra PUT/PATCH @users ========
// ======== Middleware validate userId trong PUT/PATCH ========
server.use((req, res, next) => {
  if ((req.method === 'PUT' || req.method === 'PATCH') && req.url.startsWith('/users/')) {
    const userId = req.url.split('/').pop();

    if (
      !userId ||
      userId.trim().toLowerCase() === 'null' ||
      userId.trim().toLowerCase() === 'undefined' ||
      !/^[0-9]+$/.test(userId) ||
      parseInt(userId) <= 0
    ) {
      return res.status(400).json({ message: `❌ ID '${userId}' không hợp lệ. Phải là số nguyên dương.` });
    }

    const db = router.db;
    const user = db.get('users').find({ id: userId }).value();

    if (!user) {
      return res.status(404).json({ message: `❌ Không tìm thấy user với id ${userId}` });
    }

    // ⚠️ Nếu user đang bị khóa thì không cho cập nhật
    if (user.status === 'unactive') {
      return res.status(403).json({ message: `🚫 Không thể cập nhật. User '${user.username || user.fullname}' đang bị tạm khóa.` });
    }

    const { role: newRole, password: newPassword } = req.body;

    // ⚠️ Nếu cập nhật role giống hiện tại
    if (typeof newRole !== 'undefined' && newRole === user.role) {
      return res.status(400).json({ message: `⚠️ role hiện tại đã là '${user.role}', không cần cập nhật giống nhau.` });
    }

    // ✅ Kiểm tra password nếu có
    if (typeof newPassword !== 'undefined') {
      if (newPassword === user.password) {
        return res.status(400).json({ message: '⚠️ Mật khẩu mới không được trùng với mật khẩu hiện tại.' });
      }

      if (newPassword.length < 8) {
        return res.status(400).json({ message: '❌ Mật khẩu phải có ít nhất 8 ký tự.' });
      }

      const specialCharRegex = /[!@#$%^&*(),.?":{}|<>]/;
      if (!specialCharRegex.test(newPassword)) {
        return res.status(400).json({ message: '❌ Mật khẩu phải chứa ít nhất 1 ký tự đặc biệt.' });
      }
    }
  }

  next();
});

// ======== Middleware kiểm tra PUT/PATCH @books ========
server.use((req, res, next) => {
  const { method, url, body } = req;
  if ((method === 'PUT' || method === 'PATCH') && url.match(/^\/books\/\d+$/)) {
    const { price, stock, rating, publishedYear } = body;
    const currentYear = new Date().getFullYear();
    if (price < 0 || stock < 0) return res.status(400).json({ message: '❌ price và stock không được âm.' });
    if (rating < 1 || rating > 5) return res.status(400).json({ message: '❌ rating phải từ 1 đến 5.' });
    if (publishedYear < 0 || publishedYear > currentYear)
      return res.status(400).json({ message: `❌ Năm xuất bản phải nằm trong khoảng hợp lệ (0 → ${currentYear}).` });
  }
  next();
});

// ======== Phân quyền động cho các route ========
server.use((req, res, next) => {
  const token = req.headers.authorization;
  const role = getRoleFromToken(token);
  const url = req.url.split('?')[0];

  if (req.path.startsWith('/login')) return next();
  if (req.method === 'GET' && (url.startsWith('/books') || url.startsWith('/reviews') || url.startsWith('/orders'))) return next();
  if (req.method === 'POST' && req.path.startsWith('/orders') && (role === 'admin' || role === 'user')) return next();
  if (req.method === 'POST' && req.path.startsWith('/reviews') && (role === 'admin' || role === 'user')) return next();
  if (req.method === 'POST' && req.path.startsWith('/users') && role === 'admin') return next();
  if (req.method === 'POST' && req.path.startsWith('/books') && role === 'admin') return next();
  if (role === 'admin') return next();

  // ✨ Tuỳ chỉnh message theo hành động
  if (req.method === 'DELETE' && url.startsWith('/books')) {
    return res.status(403).json({ message: '❌ Bạn không có quyền xóa sách này.' });
  }

  res.status(403).json({ message: 'Bạn không được phép truy cập tính năng.' });
});


// ======== GET /books?rating=xxx (approximate search) ========
server.get('/books', (req, res, next) => {
  const ratingParam = req.query.rating;
  if (typeof ratingParam === 'undefined') return next();

  const target = parseFloat(ratingParam);
  if (isNaN(target)) return res.status(400).json({ message: '❌ Tham số rating không hợp lệ' });

  const tolerance = 0.11;
  const books = router.db.get('books')
    .filter(book => {
      const r = parseFloat(book.rating);
      return !isNaN(r) && Math.abs(r - target) < tolerance;
    }).value();

  res.status(200).json(books);
});

// ======== Soft DELETE for books & users ========
server.use((req, res, next) => {
  if (req.method === 'DELETE') {
    const match = req.url.match(/^\/(\w+)\/([^\/\?]*)/); // Cho phép id rỗng
    if (match) {
      const [, resource, idRaw] = match;
      const id = idRaw?.trim();

      // ✅ Kiểm tra thiếu ID (rỗng/null)
      if (!id) {
        return res.status(404).json({
          message: `❌ Thiếu ID trong URL. Ví dụ đúng: /${resource}/1`
        });
      }

      // ✅ Kiểm tra định dạng ID
      if (!/^\d+$/.test(id)) {
        return res.status(400).json({
          message: `❌ ID '${id}' không đúng định dạng. Phải là số nguyên dương.`
        });
      }

      const db = router.db;
      const item = db.get(resource).find({ id }).value();

      // ✅ Kiểm tra không tìm thấy
      if (!item) {
        return res.status(404).json({
          message: `❌ Không tìm thấy ${resource} với id ${id}`
        });
      }

      // ✅ Xử lý soft delete cho books
      if (resource === 'books') {
        if (item.status === 'out_of_stock') {
          return res.status(400).json({
            message: `📦 Sách ${id} đã out_of_stock rồi.`
          });
        }
        db.get(resource).find({ id }).assign({ status: 'out_of_stock' }).write();
        return res.status(200).json({ ...item, status: 'out_of_stock' });
      }

      // ✅ Xử lý soft delete cho users
      if (resource === 'users') {
        if (item.status === 'unactive') {
          return res.status(400).json({
            message: `👤 User ${id} đã unactive rồi.`
          });
        }
        db.get(resource).find({ id }).assign({ status: 'unactive' }).write();
        return res.status(200).json({ ...item, status: 'unactive' });
      }
    }
  }

  next();
});


// ======== Kiểm tra query không hợp lệ trong GET /books ========
server.use((req, res, next) => {
  if (req.method === 'GET' && req.path === '/books') {
    const validQueryKeys = ['_sort', '_order', '_limit', '_page', 'rating', 'category', 'title', 'author', 'status', 'sort', 'price','stock','publishedYear']; // tùy bạn dùng filter gì thêm
    const receivedKeys = Object.keys(req.query);

    const invalidKeys = receivedKeys.filter(k => !validQueryKeys.includes(k));
    if (invalidKeys.length > 0) {
      return res.status(400).json({
        message: `❌ Các tham số truy vấn không hợp lệ: ${invalidKeys.join(', ')}.`,
        hint: `Chỉ được phép dùng: ${validQueryKeys.join(', ')}.`
      });
    }

    // Tiếp tục kiểm tra sort nếu có
    if ('sort' in req.query) {
      const validSortFields = ['price', 'rating', 'publishedYear'];
      if (!validSortFields.includes(req.query.sort)) {
        return res.status(400).json({
          message: `❌ Tham số 'sort=${req.query.sort}' không hợp lệ.`,
          hint: `Chỉ được phép sort theo: ${validSortFields.join(', ')}.`
        });
      }
    }
  }

  next();
});

// ======== KMiddleware kiểm tra giá trị tìm kiếm rỗng, khoảng trắng hoặc không hợp lệ GET /books ========
server.use((req, res, next) => {
  if (req.method === 'GET' && req.path === '/books') {
    const query = req.query;

    const stringFields = ['title', 'author', 'category', 'status'];
    const numberFields = ['price', 'rating', 'publishedYear'];

    const invalidFields = [];

    for (const [key, value] of Object.entries(query)) {
      if (['_sort', '_order', '_limit', '_page', 'sort'].includes(key)) continue;

      // 🧪 Kiểm tra trường chuỗi
      if (stringFields.includes(key)) {
        if (
          value === null ||
          value === undefined ||
          typeof value !== 'string' ||
          value.trim() === '' ||
          value.trim().toLowerCase() === 'null'
        ) {
          invalidFields.push(key);
        }
      }

      // 🔢 Kiểm tra trường số
      if (numberFields.includes(key)) {
        const num = parseFloat(value);
        if (
          value === null ||
          value === undefined ||
          value === '' ||
          value.toLowerCase?.() === 'null' ||
          isNaN(num) ||
          num < 0
        ) {
          invalidFields.push(key);
        }
      }
    }

    if (invalidFields.length > 0) {
      return res.status(400).json({
        message: `❌ Các tham số truy vấn không hợp lệ: ${invalidFields.join(', ')}`,
        hint: `Không được null, để trống, chỉ khoảng trắng hoặc sai kiểu dữ liệu.`
      });
    }
  }

  next();
});


// ======== Router chính xử lý dữ liệu ========
server.use(router);

// ======== 404 Not Found ========
server.use((req, res) => {
  res.status(404).json({
    message: `❌ API endpoint '${req.method} ${req.originalUrl}' không tồn tại.`,
    hint: 'Vui lòng kiểm tra lại URL và phương thức HTTP.'
  });
});

// server.listen(3000, () => {
//   console.log('🚀 Server running at http://localhost:3000');
// }); 
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
