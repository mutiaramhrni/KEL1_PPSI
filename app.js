// require("dotenv").config()
const fs = require('fs')
const express = require('express')
const mysql = require('mysql2')
const expressLayouts = require('express-ejs-layouts')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
const path=require("path")
const moment = require('moment')
const multer = require('multer')
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser')
const session = require('express-session')
const flash = require('connect-flash')
const slugify = require('slugify')


const app = express()
const port = 3000

// middleware untuk parsing request body
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());


app.set('views', path.join(__dirname, '/views'));

app.use('/css', express.static(path.resolve(__dirname, "assets/css")));
app.use('/img', express.static(path.resolve(__dirname, "assets/img")));
app.use('/submission', express.static('/img'));

// template engine
app.set('view engine', 'ejs')

// layout ejs
app.use(expressLayouts);

// mengatur folder views
app.set('views', './views');
// Middleware session
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true
}));

// Middleware flash messages
app.use(flash());

// Create multer storage configuration
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

// Create multer upload configuration
const upload = multer({ storage: storage });

// Konfigurasi koneksi ke database
const db = mysql.createConnection({
  host: 'localhost', 
  user: 'root',
  password: '',
  database: 'ppsitb' 
});

db.connect((err) => {
  if (err) {
    console.error('Gagal terkoneksi ke database:', err);
  } else {
    console.log('Terhubung ke database MySQL');
  }
});
const saltRounds = 10;

//register dan login
app.get('/register', function (req, res) {
  const errorMessage = req.session.errorMessage;
  req.session.errorMessage = ''; // Clear the error message from session
  const successMessage = req.session.successMessage;
  req.session.successMessage = '';
  res.render('register',{
    title:'Register',
    layout:'layouts/auth-layout',
    errorMessage : errorMessage,
    successMessage : successMessage
  });
})

app.post('/register', function (req, res) {
  const { username, id_user, password, confirm_password, role } = req.body;

  // cek apakah user yang regist sudah mendaftar
  const sqlCheck = 'SELECT * FROM user WHERE id_user = ?';
  db.query(sqlCheck, [id_user], (err, result) => {
    if (err) throw err;   

    if (result.length > 0) {
      console.error({ message: 'id_user sudah terdaftar', err });
      req.session.errorMessage = 'id_user sudah terdaftar';
      return res.redirect('/register');
    }
 
    if (password !== confirm_password) {
      console.error({ message: 'Password tidak cocok!', err });
      req.session.errorMessage = 'Password tidak cocok!';
      return res.redirect('/register');
    }

    // Hash password
    bcrypt.hash(password, saltRounds, function(err, hash) {
      if (err) throw err; 

      const sqlInsert = "INSERT INTO user (username, id_user, password, role) VALUES (?, ?, ?, ?)";
      const values = [username, id_user, hash, role];
      db.query(sqlInsert, values, (err, result) => {
        if (err) throw err; 
        console.log({ message: 'Registrasi berhasil', values });
        res.redirect('/login');
      });
    });
  });
});




// login page
app.get('/login', function (req, res) {
  const errorMessage = req.session.errorMessage;
  req.session.errorMessage = ''; // Clear the error message from session
  const successMessage = req.session.successMessage;
  req.session.successMessage = '';
  res.render('login',{
    title:'Login',
    layout:'layouts/auth-layout',
    errorMessage : errorMessage,
    successMessage : successMessage
  });
})

app.post('/login', function (req, res) {
  const { id_user, password } = req.body;

  const sql = `SELECT * FROM user WHERE id_user = ?`;

  db.query(sql, [id_user], function(err, result) {
    if (err) {
      console.error({ message: 'Internal Server Error', err });
      req.session.errorMessage = 'Internal Server Error';
      return res.redirect('/login');
    }
    if (result.length === 0) {
      console.error({ message: 'id_user atau Password salah!!', err });
      req.session.errorMessage = 'id_user atau Password salah!!';
      return res.redirect('/login');
    }

    const user = result[0];
 
    // compare password
    bcrypt.compare(password, user.password, function(err, isValid) {
      if (err) {
        console.error({ message: 'Internal Server Error', err });
        req.session.errorMessage = 'Internal Server Error';
        return res.redirect('/login');
      }

      if (!isValid) {
        console.error({ message: 'id_user atau Password salah!!', err });
        req.session.errorMessage = 'id_user atau Password salah!!';
        return res.redirect('/login');
      }

      // generate token
      const token = jwt.sign({ id_user: user.id_user }, 'secret_key');
      res.cookie('token', token, { httpOnly: true });

      console.log({ message: 'Login Berhasil', user });
      return res.redirect('/');
    });
  });
});



// logout
app.get('/logout', function(req, res) {
  res.clearCookie('token');
  res.redirect('/login');
});

// middleware untuk memeriksa apakah user sudah login atau belum
function requireAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) {
    res.redirect('/login');
    return;
  }
  

  jwt.verify(token, 'secret_key', function(err, decoded) {
    if (err) {
      res.redirect('/login');
      return;
    }

    req.id_user = decoded.id_user;
    next();
  });
}

app.use(requireAuth, (req, res, next) => {
  
  const query1 = `SELECT * FROM user WHERE id_user = ${req.id_user}`;
  db.query(query1, function (error, results1) {
    if (error) throw error;

    const user = results1[0];
    res.locals.user = user; 
    next();
  });
}); 

// index page
app.get('/', requireAuth, function (req, res) {
  const dsnSql = `SELECT * FROM user WHERE id_user = ${req.id_user}`;
  db.query(dsnSql, (err, result)=>{
    if (err) throw err;
    res.render('index', {
      user:result[0], 
      title: 'Home',
      layout: 'layouts/main-layout'
    }) 
  })
})

app.get('/menu', function (req, res) {
  res.render('menu', {
    title: 'Menu',
    layout: 'layouts/main-layout'
  });
});

app.get('/upload', function (req, res) {
    res.render('upload', {
      title: 'Upload',
      layout: 'layouts/main-layout'
  })
});


app.post('/upload-file', upload.single('file'), requireAuth, (req, res) => {
  let id_user = req.id_user;
  const file = req.file;

  // Pastikan file yang diupload memiliki ekstensi zip atau rar
  const allowedExtensions = ['.zip', '.rar'];
  const fileExtension = path.extname(file.originalname).toLowerCase();

  if (!allowedExtensions.includes(fileExtension)) {
    const errorMessage = 'File harus berupa format zip atau rar.';
    // Menampilkan notifikasi alert pada sisi klien
    return res.render('error',{
       message: errorMessage,
       layout : 'layouts/main-layout',
       title: 'Error'
      }
     );
  }

  const insertSql = `INSERT INTO submission (id_user, file) VALUES (?, ?)`; 
  const insertValues = [id_user, file.filename];
  
  db.query(insertSql, insertValues, (err, result) => {
    if (err) {
      throw err;
    }
    console.log({ message: 'Submission complete!', insertValues });
    res.redirect(`/kelas`);
  });
});

app.get('/about-us', requireAuth,function (req, res) {
  res.render('about-us', {
    title: 'About Us',
    layout: 'layouts/layout-berita'
});
});

app.get('/delete-file/:id_upload', (req, res) => {
  const id_upload = req.params.id_upload;

  // Hapus dari tabel anak terlebih dahulu
  const deleteGradesSql = `DELETE FROM grades WHERE id_upload = ?;`;
  db.query(deleteGradesSql, [id_upload], (err, result) => {
    if (err) {
      throw err;
    }

    // Hapus dari tabel utama
    const deleteSubmissionSql = `DELETE FROM submission WHERE id_upload = ?;`;
    db.query(deleteSubmissionSql, [id_upload], (err, result) => {
      if (err) {
        throw err;
      }

      console.log('file berhasil dihapus', { result });
      res.redirect('/kelas');
    });
  });
});



app.get('/pencarian', function (req, res) {
  res.render('pencarian', {
    title: 'pencarian',
    layout: 'layouts/main-layout'
  });
});

app.get('/beri-nilai/:id_upload/:id_user', function (req, res) {
  const id_upload = req.params.id_upload;
  const id_user = req.params.id_user;
  const gradesSql = `SELECT * FROM grades WHERE id_upload = '${id_upload}' AND id_user = '${id_user}'
   `; 
  db.query(gradesSql,  (err,results)=>{
    if (err) throw err; 
  
  res.render('beri-nilai', {
    grades:results[0],  
    id_upload:id_upload,  
    id_user:id_user,
    title: 'Penilaian',
    layout: 'layouts/main-layout'
    })
  });
});


app.post('/beri-nilai', requireAuth, (req, res) => {
  const { id_user, id_upload, grade, feedback } = req.body;

  const selectQuery = 'SELECT * FROM grades WHERE id_user = ? AND id_upload = ?';
  db.query(selectQuery, [id_user, id_upload], (selectErr, selectResults) => {
    if (selectErr) {
      console.error(selectErr);
      return;
    }

    // Check if a record exists for the user and upload ID
    if (selectResults.length === 0) {
      // If no record exists, insert a new record with the user and upload ID
      const insertQuery = 'INSERT INTO grades (id_user, id_upload) VALUES (?, ?)';
      db.query(insertQuery, [id_user, id_upload], (insertErr, insertResults) => {
        if (insertErr) {
          console.error(insertErr);
          return;
        }
        console.log('New record inserted with id_user and id_upload');
        // Proceed to update the grade and feedback
        updateGradeAndFeedback();
      });
    } else {
      // If a record already exists, directly update the grade and feedback
      updateGradeAndFeedback();
    }

    function updateGradeAndFeedback() {
      // Build the SQL query dynamically for updating grade and feedback
      let updateQuery = 'UPDATE grades SET';
      const values = [];

      if (grade) {
        updateQuery += ' grade=?';
        values.push(grade);
      }

      if (feedback) {
        if (grade) {
          updateQuery += ',';
        }
        updateQuery += ' feedback=?';
        values.push(feedback);
      }

      updateQuery += ' WHERE id_user=? AND id_upload=?';
      values.push(id_user, id_upload);

      // Perform the update for grade and feedback
      db.query(updateQuery, values, (updateErr, updateResults) => {
        if (updateErr) {
          console.error(updateErr);
          return;
        }
        console.log('Grade and feedback updated');
        res.redirect('/kelas');
      });
    }
  });
});





app.get('/kelas',requireAuth, function (req, res) {
  const id_user = req.id_user;
  const kelasSql = `SELECT kelas.*
  FROM kelas
  INNER JOIN enroll ON kelas.enroll_key = enroll.enroll_key
  INNER JOIN user ON kelas.id_user = user.id_user
  WHERE enroll.id_user = ${id_user}`;

  const kelasDsnSql = `SELECT kelas.*,  user.*
  FROM kelas
  JOIN user ON user.id_user = kelas.id_user
  WHERE user.id_user = ${id_user}`;

  db.query(kelasSql, (err,kelasResult)=>{
    if (err) throw err;
  db.query(kelasDsnSql, (err,kelasDsnResult)=>{
    if (err) throw err;
    res.render('kelas', {
      kelas : kelasResult,
      kelasDsn : kelasDsnResult,
      title: 'Kelas',
      moment:moment,
      layout: 'layouts/main-layout'
     })
    })
  })
})

app.get('/aboutus', function (req, res) {
  res.render('aboutus', {
    title: 'About Us',
    layout: 'layouts/main-layout'
  });
});

app.get('/detailKelas/:slug_kelas', requireAuth, function (req, res) {
  const slug_kelas = req.params.slug_kelas;
  let id_user = req.id_user;
  const fileSql = `SELECT submission.*, user.* FROM submission 
  JOIN user ON user.id_user = submission.id_user
  WHERE submission.id_user = ${id_user}`;
  const fileToDsn = `SELECT submission.*, user.* FROM submission 
  JOIN user ON user.id_user = submission.id_user
  WHERE submission.id_user = user.id_user`;
  const kelasSql = `SELECT * FROM kelas
  WHERE kelas.slug_kelas = ?`; 

  db.query(fileSql, (err, filesResult) => { 
    if (err) throw err; 
 
    db.query(fileToDsn, (err, fileToDsn) => {
      if (err) throw err;

    db.query(kelasSql, slug_kelas, (err, kelas) => {
      if (err) throw err;

      const detailFile = filesResult[0];
      let fileSizeInKilobytes = null;

      if (detailFile) {
        const fs = require('fs');
        const filePath = 'uploads/' + detailFile.file;
        if (fs.existsSync(filePath)) {
          const stats = fs.statSync(filePath);
          fileSizeInBytes = stats.size;
          fileSizeInKilobytes = (fileSizeInBytes / 1024).toFixed(2) + ' KB';
        }
      }

      res.render('detailKelas', {
        files: filesResult,
        filesToDsn: fileToDsn,
        kelas: kelas[0],
        moment: moment,
        fileSizeInKilobytes: fileSizeInKilobytes,
        title: 'Detail kelas',
        layout: 'layouts/main-layout'
        });
      });
    }); 
  });
});


app.get('/buat-kelas', function (req, res) {
    res.render('buat-kelas', {
      
      title: 'Buat Kelas', 
      layout: 'layouts/main-layout'
  })
}) 

app.post('/buat-kelas', requireAuth, (req, res) => {
  let id_user = req.id_user;
  const { title, enroll_key, excerpt } = req.body;

  // Menghasilkan slug dari judul
  const slug_kelas = slugify(title, {
    replacement: '-',
    lower: true,
  });

  // Insert data ke tabel 'kelas'  
  const insertKelasSql = `INSERT INTO kelas (id_user, slug_kelas, title, enroll_key, excerpt) VALUES (?, ?, ?, ?, ?)`;
  const insertKelasValues = [id_user, slug_kelas, title, enroll_key, excerpt];
  db.query(insertKelasSql, insertKelasValues, (err, kelasResult) => {
    if (err) {
      throw err;
    }
      console.log({ message: 'Create complete!', insertKelasValues });
      res.redirect('/kelas');
  });
});






app.get('/propil', requireAuth, function (req, res) {
  let id_user = req.id_user;
  const userSql = `SELECT * FROM user WHERE id_user = ${id_user}`;
  db.query(userSql, (err, Result)=>{
    if (err) throw err;
    res.render('propil', {
      user : Result[0],
      title: 'Profil',
      layout: 'layouts/main-layout'
    })
  })
}) 



app.post('/edit-propil', upload.single('avatar'), requireAuth, (req, res) => {
  const id_user = req.id_user;
  const { username, email } = req.body;
  let avatar = null;

  if (req.file) {
    // Avatar file was uploaded
    avatar = req.file.filename;

    const avatarAllowedExtensions = ['.jpg', '.jpeg', '.png'];
    const avatarExtension = path.extname(req.file.originalname).toLowerCase();

    if (!avatarAllowedExtensions.includes(avatarExtension)) {
      // Delete the invalid file
      fs.unlinkSync(req.file.path);
      res.redirect('/propil');
      return;
    }

    // Move the uploaded file to the destination directory
    const avatarSource = path.join(__dirname, 'uploads', avatar);
    const avatarDestination = path.join(__dirname, 'assets', 'img', avatar);
    fs.renameSync(avatarSource, avatarDestination);
  }

  // Build the SQL query dynamically based on whether 'avatar' is provided
  let updateQuery = 'UPDATE user SET username=?, email=?';
  const values = [username, email];

  if (avatar) {
    updateQuery += ', avatar=?';
    values.push(avatar);
  }

  updateQuery += ' WHERE id_user=?';
  values.push(id_user);

  // Update data in MySQL
  db.query(updateQuery, values, (err, result) => {
    if (err) {
      console.error(err);
      res.redirect('/propil');
      return;
    }
    console.log('Data updated in MySQL!');
    res.redirect('/propil');
  });
});


app.post('/enroll', requireAuth, function (req, res) {
  const enroll_key = req.body.enroll_key;
  const id_user = req.id_user;

  const selectSql = 'SELECT * FROM kelas WHERE enroll_key = ?';
  db.query(selectSql, [enroll_key], (err, kelasResult) => {
    if (err) {
      console.log({ message: 'Internal server erorr', err });
    }

    if (kelasResult.length > 0) {
      const id_userKelas = kelasResult[0].id_user;

      if (id_userKelas === id_user) {
        console.log({ message: 'Anda tidak bisa enroll form sendiri' });
        res.redirect('/kelas');
      } else {
        const enrollmentsSql = 'SELECT * FROM enroll WHERE id_user = ? AND enroll_key = ?';
        db.query(enrollmentsSql, [id_user, enroll_key], (enrollmentsErr, enrollmentsResult) => {
          if (enrollmentsErr) {
            console.log({ message: 'Internal server erorr', enrollmentsErr });
          }

          if (enrollmentsResult.length > 0) {
            console.log({ message: 'Anda sudah enroll pada form ini!' });
            res.redirect('/kelas');
          } else {
            const insertSql = 'INSERT INTO enroll (id_user, enroll_key) VALUES (?, ?)';
            const values = [id_user, enroll_key];
            db.query(insertSql, values, (insertErr, insertResult) => {
              if (insertErr) {
                throw insertErr;
              }

              console.log({ message: 'Enrollment berhasil' });
              res.redirect('/kelas');
            });
          }
        });
      }
    } else {
      console.log('Invalid enroll key');
    }
  });
});


app.get('/download/:id_user/:id_upload', requireAuth, (req, res) => {
  const id_user = req.params.id_user;
  const id_upload = req.params.id_upload;

  const fileSql = 'SELECT * FROM submission WHERE id_upload = ?';
  db.query(fileSql, [id_upload], function(err, fileResult) {
    if (err) throw err;
    if (fileResult.length === 0) {
      res.status(404).send('file not found');
      return;
    }

    const fileSql = 'SELECT * FROM submission WHERE id_user = ? AND id_upload = ?';
    db.query(fileSql, [id_user, id_upload], function(err, fileResult) {
      if (err) throw err;
      if (fileResult.length === 0) {
        res.status(404).send('file not found');
        return;
      }

      const file = fileResult[0];
      const filePath = `uploads/${file.file}`;

      res.download(filePath, file.file_name, function(err) {
        if (err) {
          console.log(err);
          res.status(500).send('Internal server error');
        }
      });
    });
  });
});


app.get('/search', requireAuth, (req, res) => {
  const query = req.query.query; 

  const contentSql = `
  SELECT submission.*, user.* FROM submission
  JOIN user ON user.id_user = submission.id_user
  WHERE file LIKE ?
  `;


  const searchQuery = `%${query}%`; 

    db.query(contentSql, searchQuery, (err, searchResults) => {
      if (err) {
        throw err;
      }
      const detailFile = searchResults[0];
      let fileSizeInKilobytes = null;

      if (detailFile) {
        const fs = require('fs');
        const filePath = 'uploads/' + detailFile.file;
        if (fs.existsSync(filePath)) {
          const stats = fs.statSync(filePath);
          fileSizeInBytes = stats.size;
          fileSizeInKilobytes = (fileSizeInBytes / 1024).toFixed(2) + ' KB';
        }
      } 

      res.render('search-result', { 
        title: 'Search Results',
        layout: 'layouts/main-layout',
        results: searchResults,
        fileSizeInKilobytes : fileSizeInKilobytes,
        moment: moment,
        query: query
    });
  });
});


// app.get('/search-kelas', requireAuth, (req, res) => {
//   const query = req.query.query_kelas; 

//   const contentSql = `
//   SELECT kelas.*, matkul.*
// FROM kelas
// JOIN matkul ON matkul.id_matkul = kelas.id_matkul
// WHERE matkul.matkul LIKE ? OR kelas.title LIKE ?;

//   `; 


//   const searchQuery = `%${query}%`; 

//     db.query(contentSql, searchQuery, (err, searchResults) => {
//       if (err) {
//         throw err;
//       }

//       res.render('search-kelas', {
//         title: 'Search Results',
//         layout: 'layouts/main-layout',
//         results: searchResults,
//         query: query
//     });
//   });
// });


app.listen(port,()=>{
  console.log(`listening on port ${port}`)
})