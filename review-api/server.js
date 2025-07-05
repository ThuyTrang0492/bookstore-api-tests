// server.js
const express = require('express');
const { books } = require('./db'); // không sửa db.js
const { v4: uuidv4 } = require('uuid'); // nếu muốn ID không trùng (có thể dùng Math.random nếu chưa cần UUID)

const app = express();
const PORT = 3000;

app.use(express.json());

// POST /books/:bookId/reviews
app.post('/books/:bookId/reviews', (req, res) => {
  const bookId = req.params.bookId;
  const { userId, comment, rating } = req.body;

  // Validate input
  if (!userId || !comment || rating === undefined) {
    return res.status(400).json({ error: 'Missing userId, comment, or rating' });
  }

  // Tìm sách
  const book = books.find(b => b.id === bookId);
  if (!book) {
    return res.status(404).json({ error: 'Book not found' });
  }

  // Khởi tạo reviews nếu chưa có
  if (!book.reviews) {
    book.reviews = [];
  }

  // Tạo review mới
  const newReview = {
    id: uuidv4(), // hoặc: (book.reviews.length + 1).toString()
    bookId,
    userId,
    comment,
    rating,
    createdAt: new Date().toISOString()
  };

  // Thêm vào mảng reviews
  book.reviews.push(newReview);

  // Trả về review (gói trong data nếu bạn muốn đồng nhất với Postman script)
  res.status(201).json({ data: newReview });
});

app.listen(PORT, () => {
  console.log(`✅ Server is running at http://localhost:${PORT}`);
});
