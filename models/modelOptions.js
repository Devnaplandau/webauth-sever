//định nghĩa model để nhận data từ moogodb thông qua Schema interface
exports.schemaOptions = {
  toJSON: {
    virtuals: true,
  },
  toObject: {
    virtuals: true,
  },
  timestamps: true,
};
